#pragma once

#include <map>

#include "Application.hh"
#include "Loader.hh"
#include "Switch.hh"
#include "HostManager.hh"
#include "Flow.hh"
#include "types/ethaddr.hh"
#include <fluid/of13/of13match.hh>

/**
 * Address pair allows to save IP and Ethernet addresses in the one simple
 * struct.
 */
struct address_pair {
	uint32_t ip;
	uint64_t eth;
	address_pair(uint32_t ip, uint64_t eth);
};

struct BalancerHost;

/**
 * Describe parameters of one of balanced flows.
 */
struct BalancerFlow {
	/**
	 * Address of the served client, i.e. the host that is not balanced, but
	 * works with one of balanced servers.
	 */
	address_pair client;
	/**
	 * Address to which the client sends requests and from which waits
	 * answers.
	 */
	address_pair server;
	/**
	 * Backend server, that actually serves requests of the client. This
	 * address can differ from the server to which the client sends
	 * requests.
	 */
	address_pair hidden;
	/** Balanced host which server client requests. */
	BalancerHost *host;
	/** Flow cookie, that was assigned to it by the controller. */
	uint64_t cookie;

	BalancerFlow(const address_pair &client, const address_pair &server,
		     const address_pair &hidden, BalancerHost *host,
		     uint64_t cookie);
};
using BalancerFlow_p = std::shared_ptr<BalancerFlow>;

/**
 * Backend host that serves client requests, that can be addressed not to it.
 */
struct BalancerHost {
	address_pair addr;
	/** Port of the switch to which the host is connected. */
	uint32_t switch_port;
	/** These flows are serving by the host. */
	std::list<BalancerFlow_p> flows;
	/** True if the host is active and can accept new client. */
	bool is_up;
	BalancerHost(const address_pair &addr);
};
using BalancerHost_p = std::shared_ptr<BalancerHost>;

using namespace runos;

class Homework : public Application {
SIMPLE_APPLICATION(Homework, "homework")
public:
	void init(Loader* loader, const Config& config) override;

private:
	HostManager *manager;
	/** DPID of the balanced switch. */
	uint64_t balancer_dpid;
	/** Idle timeout for flow rules on the balanced switch. */
	uint16_t idle_timeout;
	/** Map with IP keys and host values. */
	std::map<uint32_t, BalancerHost_p> bhosts;
	/** List of all flows through the balanced switch. */
	std::list<BalancerFlow_p> flows;
	SwitchManager *switch_manager;
	/** All balanced flows are stored in this table. */
	uint8_t table_no;
	/**
	 * Balanced hosts are filled with their switch ports and mac addresses.
	 */
	bool hosts_discovered;
	/**
	 * Balanced switch is listen on port up/down events.
	 */
	bool switch_connected;

	/**
	 * Find the flow from the specified client to the server specified by
	 * the client.
	 * @param client_mac MAC address of the client host.
	 * @param server_mac MAC address of the server host.
	 *
	 * @retval nullptr     Not found.
	 * @retval not nullptr Flow, that was found.
	 */
	BalancerFlow *
	find_flow(uint64_t client_mac, uint64_t server_mac);

	/**
	 * Find a balanced host by its MAC address.
	 * @param server_mac MAC address
	 *
	 * @retval nullptr     Host wasn't found.
	 * @retval not nullptr Host that was found.
	 */
	BalancerHost *
	find_host(uint64_t server_mac);

	/**
	 * Balance the new flow to one of balanced servers.
	 * @param client Address of the client host.
	 * @param server Server of the client host.
	 * @param cookie Cookie of the flow.
	 *
	 * @retval new flow.
	 */
	BalancerFlow *
	add_new_flow(const address_pair &client, const address_pair &server,
		     uint64_t cookie);

	/**
	 * Read the config and initialize internal settings.
	 * @retval true  Success.
	 * @retval false Error while parsing config.
	 */
	bool
	initialize_config();

	/**
	 * Find which Ethernet addresses and switch ports balanced servers have.
	 */
	void
	discover_hosts();

	void
	connect_switch();

private slots:
	/**
	 * If a flow was removed from switch then remove it from its backend
	 * server.
	 * @param ofconnl Switch connection.
	 * @param cookie  Cookie of the removed flow.
	 */
	void
	slot_flow_removed(SwitchConnectionPtr ofconnl, uint64_t cookie);

	void
	slot_port_up(Switch* dp, of13::Port port);

	void
	slot_port_down(Switch* dp, uint32_t port_no);
};
