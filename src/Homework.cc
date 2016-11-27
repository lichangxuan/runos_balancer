#include "Homework.hh"

#include <sstream>
#include <iomanip>
#include <assert.h>
#include <arpa/inet.h>

#include <QFile>
#include <QByteArray>

#include "api/Packet.hh"
#include "api/PacketMissHandler.hh"
#include "oxm/openflow_basic.hh"
#include "types/ethaddr.hh"

#include "Controller.hh"
#include "Switch.hh"
#include "SwitchConnection.hh"
#include "Flow.hh"
#include "Common.hh"
#include "Topology.hh"

/** Always return hard_timeout(zero), because else maple will add bad rules. */
#define DECISION_ZERO decision.hard_timeout(std::chrono::seconds::zero())

enum network_layer_proto {
	IPv4_PROTO = 0x0800
};

enum transport_layer_proto {
	TCP_PROTO = 6
};

address_pair::address_pair(uint32_t ip, uint64_t eth)
	: ip(ip), eth(eth)
{ }

/* Print the address to the out stream in the readable format. */
std::ostream &
operator<<(std::ostream &stream, const address_pair &ob)
{
	stream << "eth = " << ethaddr(ob.eth)
	       << ", ip = " << AppObject::uint32_t_ip_to_string(ob.ip);
	return stream;
}

BalancerFlow::BalancerFlow(const address_pair &client,
			   const address_pair &server,
			   const address_pair &hidden, BalancerHost *host,
			   uint64_t cookie)
	: client(client), server(server), hidden(hidden), host(host),
	  cookie(cookie)
{ }

/* Print the flow to the out stream in the readable format. */
std::ostream &
operator<<(std::ostream &stream, const BalancerFlow &ob)
{
	stream << "client: [" << ob.client << "], server: ["
	       << ob.server << "], hidden: [" << ob.hidden << "]";
	return stream;
}

BalancerHost::BalancerHost(const address_pair &addr)
	: addr(addr), is_up(true)
{ }

REGISTER_APPLICATION(Homework, {"controller", "switch-manager", "topology",
				"host-manager", ""})

using namespace runos;

/**
 * RUNOS engine unfortunately hasn't easy ways to convert the uint64 number to
 * an Ethernet address.
 * @param num Ethernet address.
 * @retval EthAddress that can be used for FlowMod rules construction.
 */
EthAddress
get_ethernet_from_number(uint64_t num)
{
	ethaddr addr(num);
	uint8_t *bytes = addr.to_octets().data();
	return EthAddress(bytes);
}

/**
 * Get several fields from PacketIn, that are:
 * - Ethernet source, destination
 * - IP source, destination
 * - string representation of IPs
 * @param pkt      PacketIn
 * @param[out] src        Where to save IP and Ethernet of the source.
 * @param[out] dst        Where to save IP and Ethernet of the destination.
 * @param[out] ip_src_str Where to save a string representation of the source
 *                        IP.
 * @param[out] ip_dst_str Where to save a string representation of the
 *                        destination.
 */
void
load_addresses_from_packet(Packet &pkt, address_pair *src, address_pair *dst,
			   std::string *ip_src_str, std::string *ip_dst_str)
{
	uint32_t ip_src, ip_dst;
	uint64_t eth_src, eth_dst;
	ip_src = htonl(pkt.load(oxm::ipv4_src()));
	ip_dst = htonl(pkt.load(oxm::ipv4_dst()));
	eth_src = ethaddr(pkt.load(oxm::eth_src())).to_number();
	eth_dst = ethaddr(pkt.load(oxm::eth_dst())).to_number();
	*src = address_pair(ip_src, eth_src);
	*dst = address_pair(ip_dst, eth_dst);
	*ip_src_str = AppObject::uint32_t_ip_to_string(ip_src);
	*ip_dst_str = AppObject::uint32_t_ip_to_string(ip_dst);
}

/**
 * Create a FlowMod message, that redirects the traffic from the client to the
 * balanced backend server of the specified flow.
 * @param bflow        New flow description.
 * @param cookie       Cookie of the new flow.
 * @param table_no     Number of the rules table, in which the new flow will be
 *                     saved.
 * @param out_port     Switch port of the backend server.
 * @param idle_timeout After this seconds count the created flow will be
 *                     removed.
 *
 * @retval Constructed FlowMod message.
 */
of13::FlowMod
create_client_server_flowmod(const BalancerFlow *bflow, uint64_t cookie,
			     uint8_t table_no, uint16_t out_port,
			     uint16_t idle_timeout)
{
	of13::FlowMod fm;
	of13::ApplyActions act;
	Action *action;
	EthAddress eth;
	const address_pair &back = bflow->hidden;
	const address_pair &src = bflow->client;
	const address_pair &dst = bflow->server;

	/* Redirect the flow to the hidden server. */

	fm.command(of13::OFPFC_ADD);
	fm.priority(1);
	fm.table_id(table_no);
	fm.cookie(cookie);
	fm.out_port(out_port);
	fm.idle_timeout(idle_timeout);
	fm.flags(of13::OFPFF_SEND_FLOW_REM);

	/* Match fields. */

	fm.add_oxm_field(new of13::IPProto(TCP_PROTO));
	fm.add_oxm_field(new of13::EthType(IPv4_PROTO));

	eth = get_ethernet_from_number(dst.eth);
	fm.add_oxm_field(new of13::EthDst(eth));
	fm.add_oxm_field(new of13::IPv4Dst(dst.ip));

	eth = get_ethernet_from_number(src.eth);
	fm.add_oxm_field(new of13::EthSrc(eth));
	fm.add_oxm_field(new of13::IPv4Src(src.ip));

	/* Actions. */

	eth = get_ethernet_from_number(back.eth);
	action = new of13::SetFieldAction(new of13::EthDst(eth));
	act.add_action(action);

	action = new of13::SetFieldAction(new of13::IPv4Dst(back.ip));
	act.add_action(action);

	action = new of13::OutputAction(out_port, 0);
	act.add_action(action);

	fm.add_instruction(act);
	return fm;
}

/**
 * Create a FlowMod message, that redirects the traffic from the backend server
 * to the client and changes a source address to expected by the client.
 * @param bflow        New flow description.
 * @param cookie       Cookie of the new flow.
 * @param table_no     Number of the rules table, in which the new flow will be
 *                     saved.
 * @param out_port     Switch port of the backend server.
 * @param idle_timeout After this seconds count the created flow will be
 *                     removed.
 *
 * @retval Constructed FlowMod message.
 */
of13::FlowMod
create_server_client_flowmod(const BalancerFlow *bflow, uint64_t cookie,
			       uint8_t table_no, int16_t out_port,
			       uint16_t idle_timeout)
{
	of13::FlowMod fm;
	of13::ApplyActions act;
	Action *action;
	EthAddress eth;
	const address_pair &back = bflow->hidden;
	const address_pair &src = bflow->client;
	const address_pair &dst = bflow->server;

	/* Change the flow from the hidden server. */

	fm.command(of13::OFPFC_ADD);
	fm.priority(1);
	fm.table_id(table_no);
	fm.cookie(cookie);
	fm.out_port(out_port);
	fm.idle_timeout(idle_timeout);
	fm.flags(of13::OFPFF_SEND_FLOW_REM);

	/* Match fields. */

	fm.add_oxm_field(new of13::IPProto(TCP_PROTO));
	fm.add_oxm_field(new of13::EthType(IPv4_PROTO));

	eth = get_ethernet_from_number(back.eth);
	fm.add_oxm_field(new of13::EthSrc(eth));
	fm.add_oxm_field(new of13::IPv4Src(back.ip));

	eth = get_ethernet_from_number(src.eth);
	fm.add_oxm_field(new of13::EthDst(eth));
	fm.add_oxm_field(new of13::IPv4Dst(src.ip));

	/* Actions. */

	eth = get_ethernet_from_number(dst.eth);
	action = new of13::SetFieldAction(new of13::EthSrc(eth));
	act.add_action(action);

	action = new of13::SetFieldAction(new of13::IPv4Src(dst.ip));
	act.add_action(action);

	action = new of13::OutputAction(out_port, 0);
	act.add_action(action);

	fm.add_instruction(act);
	return fm;
}

/**
 * Create a FlowMod message, that forwards the traffic from the source to the
 * destination addresses.
 * @param src          Source address.
 * @param dst          Destination address.
 * @param tcp_src      TCP port on the source address.
 * @param cookie       Cookie of the new flow.
 * @param table_no     Number of the rules table, in which the new flow will be
 *                     saved.
 * @param out_port     Port to which need to forward.
 * @param idle_timeout After this seconds count the created flow will be
 *                     removed.
 *
 * @retval Constructed FlowMod message.
 */
of13::FlowMod
create_not_balanced(const address_pair &src, const address_pair &dst,
		    uint16_t tcp_src, uint64_t cookie, uint8_t table_no,
		    uint16_t out_port, uint16_t idle_timeout)
{
	of13::FlowMod fm;
	of13::ApplyActions act;
	Action *action;
	EthAddress eth;

	fm.command(of13::OFPFC_ADD);
	fm.priority(1);
	fm.table_id(table_no);
	fm.cookie(cookie);
	fm.out_port(out_port);
	fm.idle_timeout(idle_timeout);

	/* Match fields. */

	fm.add_oxm_field(new of13::IPProto(TCP_PROTO));
	fm.add_oxm_field(new of13::EthType(IPv4_PROTO));

	eth = get_ethernet_from_number(dst.eth);
	fm.add_oxm_field(new of13::EthDst(eth));
	fm.add_oxm_field(new of13::IPv4Dst(dst.ip));
	if (tcp_src != 0)
		fm.add_oxm_field(new of13::TCPSrc(tcp_src));

	eth = get_ethernet_from_number(src.eth);
	fm.add_oxm_field(new of13::EthSrc(eth));
	fm.add_oxm_field(new of13::IPv4Src(src.ip));

	/* Actions. */

	action = new of13::OutputAction(out_port, 0);
	act.add_action(action);

	fm.add_instruction(act);
	return fm;
}

/**
 * Create flow mod that deletes flows with the specified cookie.
 * @param cookie   Delete by this cookie.
 * @param table_no Delete from this table.
 *
 * @retval Created flow mod.
 */
of13::FlowMod
delete_flow(uint64_t cookie, uint8_t table_no)
{
	of13::FlowMod fm;
	fm.command(of13::OFPFC_DELETE);
	fm.priority(1);
	fm.table_id(table_no);
	fm.cookie(cookie);

	return fm;
}

/**
 * Find a host by the IP.
 * @param manager Host manager of the controller.
 * @param ip IP address of the host.
 *
 * @retval nullptr     Not found.
 * @retval not nullptr Host that was found.
 */
Host *
findHost(HostManager *manager, uint32_t ip)
{
	std::string str_ip = AppObject::uint32_t_ip_to_string(ip);
	for (auto it = manager->hosts().begin(), end = manager->hosts().end();
	     it != end; ++it) {
		Host *host = it->second;
		if (str_ip == host->ip())
			return host;
	}
	return nullptr;
}

void
Homework::init(Loader *loader, const Config &)
{
	/* Get global object for managing flows. */
	Controller *ctrl = Controller::get(loader);
	manager = HostManager::get(loader);
	Topology *topo = Topology::get(loader);
	switch_manager = SwitchManager::get(loader);
	assert(manager != nullptr);
	assert(ctrl != nullptr);
	assert(topo != nullptr);
	assert(switch_manager != nullptr);

	connect(ctrl, &Controller::flowRemoved,
		this, &Homework::slot_flow_removed);

	if (!initialize_config())
		return;

	table_no = ctrl->reserveTable();


	ctrl->registerHandler("homework",
	[=](SwitchConnectionPtr connection) {
		uint32_t dpid = connection->dpid();

		return [=](Packet& pkt, FlowPtr flow, Decision decision) {
			/* Process only packets to the balanced switch. */
			if(dpid != balancer_dpid)
				return decision;

			/* Process only IPv4 network level flows. */
			uint64_t eth_type = pkt.load(oxm::eth_type());
			if (eth_type != IPv4_PROTO)
				return DECISION_ZERO;

			/* Process only TCP transport level flows. */
			uint64_t ip_proto = pkt.load(oxm::ip_proto());
			if (ip_proto != TCP_PROTO)
				return DECISION_ZERO;
			uint32_t in_port = pkt.load(oxm::in_port());
			LOG(INFO) << "Start processing PacketIn...";

			address_pair src(0, 0), dst(0, 0);
			std::string ip_src_str, ip_dst_str;
			load_addresses_from_packet(pkt, &src, &dst,
						   &ip_src_str, &ip_dst_str);

			auto dest_host = bhosts.find(dst.ip);
			auto src_host = bhosts.find(src.ip);
			auto not_found = bhosts.end();

			/* No balancers in this flow. */
			if (dest_host == not_found && src_host == not_found)
				return DECISION_ZERO;

			/* Flow from one balancer to another. */
			if (src_host != not_found && dest_host != not_found)
				return DECISION_ZERO;

			uint64_t cookie = flow->cookie();

			if (!hosts_discovered)
				discover_hosts();
			if (!switch_connected)
				connect_switch();

			/* Flow from the balanced host to a client. */
			if (src_host != not_found) {
				uint16_t tcp_dst = pkt.load(oxm::tcp_dst());
				of13::FlowMod fm;
				/* Find the server and its switch port. */
				BalancerHost *host = find_host(src.eth);
				assert(host != nullptr);

				/*
				 * Forward the traffic from the client to the
				 * server without balancing.
				 */
				fm = create_not_balanced(dst, src, tcp_dst,
							 cookie, table_no,
							 host->switch_port,
							 idle_timeout);
				connection->send(fm);

				/*
				 * Get the client host and calculate a route
				 * from the server switch to the client switch.
				 */
				IPAddress ip_addr(htonl(dst.ip));
				Host *client_host = manager->getHost(ip_addr);
				assert(client_host != NULL);
				uint64_t client_switch;
				client_switch = client_host->switchID();
				auto route = topo->computeRoute(dpid,
								client_switch);
				/*
				 * Forward the traffic from the server to the
				 * client now to avoid future packetin-s of
				 * answers.
				 */
				fm = create_not_balanced(src, dst, 0, cookie,
							 table_no,
							 route[0].port,
							 idle_timeout);
				connection->send(fm);
				return DECISION_ZERO;
			}

			/*
			 * Process the flow from the client to one of balanced
			 * hosts.
			 */
			LOG(INFO) << "new flow: eth_src = " << ethaddr(src.eth)
				  << ", eth_dst = " << ethaddr(dst.eth)
				  << ", ip_src = " << ip_src_str
				  << ", ip_dst = " << ip_dst_str;
			assert(dest_host != not_found);

			/* Try to find an existing flow. */
			BalancerFlow *bflow = find_flow(src.eth, dst.eth);
			if (bflow != nullptr)
				/* Already is balanced. */
				return DECISION_ZERO;

			/* Balance the new flow to one of balanced servers. */
			bflow = add_new_flow(src, dst, cookie);
			if (bflow == nullptr)
				return DECISION_ZERO;

			/*
			 * If met the packet to the balanced server then rediret
			 * to the hidden server.
			 */
			uint16_t out_port = bflow->host->switch_port;
			of13::FlowMod fm;
			fm = create_client_server_flowmod(bflow, cookie,
							  table_no, out_port,
							  idle_timeout);
			connection->send(fm);

			/*
			 * If met the packet from the hidden server then change
			 * src to the original server.
			 */
			fm = create_server_client_flowmod(bflow, cookie,
							  table_no, in_port,
							  idle_timeout);
			connection->send(fm);

			return DECISION_ZERO;
		};
	});
}

BalancerFlow *
Homework::add_new_flow(const address_pair &client, const address_pair &server,
		       uint64_t cookie)
{
	/* Find a most free host. */
	BalancerHost *most_free = bhosts.begin()->second.get();
	assert(most_free != nullptr);
	for (auto it = bhosts.begin(), end = bhosts.end(); it != end; ++it) {
		BalancerHost *host = it->second.get();
		if (!host->is_up)
			continue;
		if (!most_free->is_up) {
			most_free = host;
			continue;
		}
		if (it->second->flows.size() < most_free->flows.size())
			most_free = it->second.get();
	}
	assert(most_free != nullptr);
	if (!most_free->is_up)
		return nullptr;

	/* Add the new flow to the found host. */
	std::shared_ptr<BalancerFlow> new_flow;
	new_flow.reset(new BalancerFlow(client, server, most_free->addr,
					most_free, cookie));

	most_free->flows.push_back(new_flow);

	/* Add the new flow to the list of all flows. */
	flows.push_back(new_flow);
	LOG(INFO) << "choosed host on port " << most_free->switch_port;
	return new_flow.get();
}

BalancerFlow *
Homework::find_flow(uint64_t client_mac, uint64_t server_mac)
{
	for (auto it = flows.begin(), end = flows.end(); it != end; ++it) {
		if (it->get()->client.eth == client_mac &&
		    it->get()->server.eth == server_mac)
			return it->get();
	}
	return nullptr;
}

BalancerHost *
Homework::find_host(uint64_t server_mac)
{
	for (auto it = bhosts.begin(), end = bhosts.end(); it != end; ++it) {
		BalancerHost *host = it->second.get();
		if (host->addr.eth == server_mac)
			return host;
	}
	return nullptr;
}

bool
Homework::initialize_config()
{
	hosts_discovered = false;
	switch_connected = false;
	/* Initialize settings of the balancer by default values. */

	QFile file("balancer_settings.json");
	if (!file.open(QIODevice::ReadOnly)) {
		LOG(INFO) << "balancer_settings.json not open";
		return false;
	}
	QByteArray data = file.readAll();
	std::string config_file(data.data(), data.size());
	std::string err;
	json11::Json json_config = json11::Json::parse(config_file, err);
	if (err.length() > 0) {
		LOG(INFO) << "error while parsing balancer config: " << err;
		return false;
	}
	if (!json_config.is_object()) {
		LOG(INFO) << "balancer_settings must be JSON map";
		return false;
	}
	json11::Json::object config = json_config.object_items();
	auto not_found = config.end();
	if (config.find("dpid") == not_found) {
		LOG(INFO) << "dpid is not specified";
		return false;
	}
	json11::Json json_dpid = config["dpid"];
	if (!json_dpid.is_number()) {
		LOG(INFO) << "dpid must be positive number";
		return false;
	}
	balancer_dpid = json_dpid.int_value();
	if (balancer_dpid <= 0) {
		LOG(INFO) << "dpid must be positive number";
		return false;
	}
	LOG(INFO) << "dpid was read: " << balancer_dpid;

	json11::Json json_idle = config["idle_timeout"];
	if (!json_idle.is_number()) {
		LOG(INFO) << "idle_timeout must be positive number";
		return false;
	}
	idle_timeout = json_idle.int_value();

	LOG(INFO) << "idle_timeout was read: " << idle_timeout;

	json11::Json json_hosts = config["hosts"];
	if (!json_hosts.is_array()) {
		LOG(INFO) << "hosts must be array";
		return false;
	}
	const json11::Json::array &hosts_array = json_hosts.array_items();
	for (size_t i = 0, size = hosts_array.size(); i < size; ++i) {
		const json11::Json &json_host = hosts_array[i];
		if (!json_host.is_string()) {
			LOG(INFO) << "each host must be string";
			return false;
		}
		LOG(INFO) << "ip was read: " << json_host.string_value();
		uint32_t ip = IPAddress(json_host.string_value()).getIPv4();
		address_pair addr(ip, 0);
		std::shared_ptr<BalancerHost> host(new BalancerHost(addr));
		bhosts.insert(std::make_pair(ip, host));
	}
	return true;
}

void
Homework::discover_hosts()
{
	assert(!hosts_discovered);
	for (auto it = bhosts.begin(), end = bhosts.end(); it != end; ++it) {
		BalancerHost *bhost = it->second.get();
		uint32_t search_ip = htonl(bhost->addr.ip);
		Host *host = manager->getHost(IPAddress(search_ip));
		if (host == nullptr) {
			LOG(INFO) << "host not found";
			continue;
		}
		LOG(INFO) << "host is found";
		bhost->switch_port = host->switchPort();
		bhost->addr.eth = ethaddr(host->mac()).to_number();
	}
	hosts_discovered = true;
}

void
Homework::connect_switch()
{
	Switch *sw = switch_manager->getSwitch(balancer_dpid);
	if (sw == nullptr) {
		LOG(INFO) << "no such balancer switch";
	} else {
		connect(sw, &Switch::portUp,
			this, &Homework::slot_port_up);
		connect(sw, &Switch::portDown,
			this, &Homework::slot_port_down);
		switch_connected = true;
	}
}

void
Homework::slot_flow_removed(SwitchConnectionPtr ofconnl, uint64_t cookie)
{
	(void) ofconnl;
	auto it = flows.begin(), end = flows.end();
	for (; it != end; ++it) {
		if (it->get()->cookie == cookie)
			break;
	}
	/* If was removed a not balanced flow the ignore it. */
	if (it == end)
		return;

	BalancerFlow *flow = it->get();
	BalancerHost *host = flow->host;
	flows.erase(it);
	for (it = host->flows.begin(), end = host->flows.end(); it != end;
	     ++it) {
		if (it->get()->cookie == cookie)
			break;
	}
	assert(it != end);
	host->flows.erase(it);
	LOG(INFO) << "Flow removed";
}

void
Homework::slot_port_up(Switch* dp, of13::Port port)
{
	(void)dp;
	LOG(INFO) << "port is up";
	uint32_t port_no = port.port_no();
	for (auto it = bhosts.begin(), end = bhosts.end(); it != end; ++it) {
		BalancerHost *host = it->second.get();
		if (host->switch_port == port_no) {
			host->is_up = true;
			return;
		}
	}
}

void
Homework::slot_port_down(Switch* dp, uint32_t port_no)
{
	(void)dp;
	LOG(INFO) << "port is down";
	for (auto it = bhosts.begin(), end = bhosts.end(); it != end; ++it) {
		BalancerHost *host = it->second.get();
		if (host->switch_port == port_no) {
			host->is_up = false;
			/* Delete all flows of this host. */
			for (auto flow = host->flows.begin(),
			     fend = host->flows.end(); flow != fend; ++flow) {
				of13::FlowMod fm = delete_flow((*flow)->cookie,
							       table_no);
				auto conn = dp->connection();
				conn->send(fm);
			}
			return;
		}
	}
}
