 /*// us file is part of NOX.
 *
 * NOX is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * NOX is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with NOX.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <boost/bind.hpp>
#include <boost/foreach.hpp>
#include <boost/shared_array.hpp>
#include <cstring>
#include <netinet/in.h>
#include <stdexcept>
#include <stdint.h>

#include "openflow-default.hh"
#include "assert.hh"
#include "component.hh"
#include "flow.hh"
#include "fnv_hash.hh"
#include "hash_set.hh"
#include "ofp-msg-event.hh"
#include "vlog.hh"
#include "flowmod.hh"
#include "datapath-join.hh"
#include <stdio.h>

#include <stdio.h>
#include "netinet++/ethernetaddr.hh"
#include "netinet++/ethernet.hh"

#include "../../../oflib/ofl-actions.h"
#include "../../../oflib/ofl-messages.h"

using namespace vigil;
using namespace vigil::container;
using namespace std;

namespace {

struct Mac_source
{
	/* Datapath에는 연결된 OpenFlow 스위치에 해당하는 정보가 저장 */
    /* Key. */
    datapathid datapath_id;     /* Switch. */
    ethernetaddr mac;           /* Source MAC. */

    /* Value. */
    mutable int port;           /* Port where packets from 'mac' were seen. */

    Mac_source() : port(-1) { }
    Mac_source(datapathid datapath_id_, ethernetaddr mac_)
        : datapath_id(datapath_id_), mac(mac_), port(-1)
        { }
};

bool operator==(const Mac_source& a, const Mac_source& b)
{
    return a.datapath_id == b.datapath_id && a.mac == b.mac;
}

bool operator!=(const Mac_source& a, const Mac_source& b) 
{
    return !(a == b);
}

struct Hash_mac_source
{
    std::size_t operator()(const Mac_source& val) const {
        uint32_t x;
        x = vigil::fnv_hash(&val.datapath_id, sizeof val.datapath_id);
        x = vigil::fnv_hash(val.mac.octet, sizeof val.mac.octet, x);
        return x;
    }
};

Vlog_module log("switch");

class Switch
    : public Component 
{
public:
    Switch(const Context* c,
           const json_object*) 
        : Component(c) { }

    void configure(const Configuration*);

    void install();

    Disposition handle(const Event&);
    Disposition handle_dp_join(const Event& e);
	Disposition flow_stats_reply_handler(const Event & e);
	Disposition aggregate_stats_reply_handler(const Event & e);

private:
    typedef hash_set<Mac_source, Hash_mac_source> Source_table;
    Source_table sources;

	datapathid dp[1];
	timeval tv;

	void monitor();
	void request_flow_stats(const datapathid& dpid);
	void request_aggregate_stats(const datapathid& dpid);

    /* Set up a flow when we know the destination of a packet?  This should
     * ordinarily be true; it is only usefully false for debugging purposes. */
    bool setup_flows;
};

void 
Switch::configure(const Configuration* conf) {
    setup_flows = true; // default value
    BOOST_FOREACH (const std::string& arg, conf->get_arguments()) {
        if (arg == "noflow") {
            setup_flows = false;
        } else {
            VLOG_WARN(log, "argument \"%s\" not supported", arg.c_str());
        }
    }

    register_handler(Datapath_join_event::static_get_name(), boost::bind(&Switch::handle_dp_join, this, _1));
    register_handler(Ofp_msg_event::get_name(OFPT_PACKET_IN), boost::bind(&Switch::handle, this, _1));
	register_handler(Ofp_msg_event::get_stats_name(OFPMP_FLOW), boost::bind(&Switch::flow_stats_reply_handler, this, _1));
	register_handler(Ofp_msg_event::get_stats_name(OFPMP_AGGREGATE), boost::bind(&Switch::aggregate_stats_reply_handler, this, _1));
}

void
Switch::install() {
	post(boost::bind(&Switch::monitor, this));
}

Disposition
Switch::handle_dp_join(const Event& e){
  const Datapath_join_event& dpj = assert_cast<const Datapath_join_event&>(e);

	/* OpenFlow 스위치와의 핸드 셰이크가 완료된 후, Table-miss 플로우 항목(entry)이 플로우 테이블에 추가됨 */
    /* The behavior on a flow miss is to drop packets
       so we need to install a default flow */
    VLOG_DBG(log,"Installing default flow with priority 0 to send packets to the controller on dpid= 0x%"PRIx64"\n", dpj.dpid.as_host());
    Flow  *f = new Flow();

	/* 컨트롤러 포트로 전송하는 OUTPUT 액션 생성 */
    Actions *acts = new Actions();
    acts->CreateOutput(OFPP_CONTROLLER);
    Instruction *inst =  new Instruction();
    inst->CreateApply(acts);

	/* Flow mod 메세지를 발행하여 플로우 테이블에 항목을 추가 */
	/* 모든 패킷에 매치시키기 위해 빈 Match 생성 */
	/* Table-miss 플로우 항목은 우선 순위가 최저(0)이고, 모든 패킷에 매치되는 항목 */
    FlowMod *mod = new FlowMod(0x00ULL,0x00ULL, 0,OFPFC_ADD, OFP_FLOW_PERMANENT, OFP_FLOW_PERMANENT, 0, 0, 
                                OFPP_ANY, OFPG_ANY, ofd_flow_mod_flags());
    mod->AddMatch(&f->match);
    mod->AddInstructions(inst);
    send_openflow_msg(dpj.dpid, (struct ofl_msg_header *)&mod->fm_msg, 0/*xid*/, true/*block*/);
    
	dp[0] = dpj.dpid;

    return CONTINUE;

}

Disposition
Switch::handle(const Event& e)
{
    const Ofp_msg_event& pi = assert_cast<const Ofp_msg_event&>(e);

    struct ofl_msg_packet_in *in = (struct ofl_msg_packet_in *)**pi.msg;
    Flow *flow = new Flow((struct ofl_match*) in->match);

    /* drop all LLDP packets */
        uint16_t dl_type;
        flow->get_Field<uint16_t>("eth_type",&dl_type);
        if (dl_type == ethernet::LLDP){
            return CONTINUE;
        }
       
	/* match에서 수신 포트(in_port)를 가져옴 */
    uint32_t in_port;
    flow->get_Field<uint32_t>("in_port", &in_port);        
	
   
    /* Learn the source. */
    uint8_t eth_src[6];
    flow->get_Field("eth_src", eth_src);
    ethernetaddr dl_src(eth_src);
    if (!dl_src.is_multicast()) {
	/* MAC 주소와 수신 포트 번호를 기반으로 MAC 주소 테이블 업데이트 */
        Mac_source src(pi.dpid, dl_src);
        Source_table::iterator i = sources.insert(src).first;

        if (i->port != in_port) {
            i->port = in_port;
            VLOG_DBG(log, "learned that "EA_FMT" is on datapath %s port %d",
                     EA_ARGS(&dl_src), pi.dpid.string().c_str(),
                     (int) in_port);
        }
    } else {
        VLOG_DBG(log, "multicast packet source "EA_FMT, EA_ARGS(&dl_src));
    }

	/* 대상 MAC 주소가 MAC 주소 테이블에 존재하는 경우 대응되는 포트 번호가 사용. 발견되지 않으면 플러딩(OFPP_FLOOD)를 출력 포트에 지정 */
    /* Figure out the destination. */
    int out_port = -1;        /* Flood by default. */
    uint8_t eth_dst[6];
    flow->get_Field("eth_dst", eth_dst);
    ethernetaddr dl_dst(eth_dst);
    if (!dl_dst.is_multicast()) {
        Mac_source dst(pi.dpid, dl_dst);
	Source_table::iterator i(sources.find(dst));
        if (i != sources.end()) {
            out_port = i->port;
        }
    }
		
	/* 대상 MAC 주소가 있으면 OpenFlow 스위치의 플로우 테이블에 항목을 추가 */
    /* Set up a flow if the output port is known. */
    if (setup_flows && out_port != -1) {

    /* 매치 조건 설정. 수신 포트(in_port)와 대상 MAC 주소(eth_dst) 지정. ex) port 1에서 수신하고 호스트 B로 향하는 패킷 */
	Flow  f;
	f.Add_Field("in_port", in_port);
	f.Add_Field("eth_src", eth_src);
	f.Add_Field("eth_dst",eth_dst);
	Actions *acts = new Actions();
    acts->CreateOutput(out_port);
    Instruction *inst =  new Instruction();
    inst->CreateApply(acts);
	/* 플로우 항목(flow entry)의 우선 순위 1. Table-miss 항목보다 먼저 평가 */
	/* Flow mod command. OPFPC_ADD: 새로운 플로우 항목을 추가 */
    FlowMod *mod = new FlowMod(0x00ULL,0x00ULL, 0,OFPFC_ADD, 1, OFP_FLOW_PERMANENT, OFP_DEFAULT_PRIORITY,in->buffer_id, 
                                    OFPP_ANY, OFPG_ANY, ofd_flow_mod_flags());
    mod->AddMatch(&f.match);
	mod->AddInstructions(inst);
	/* Flow mod 메세지를 발행하여 플로우 테이블에 항목을 추가 */
    send_openflow_msg(pi.dpid, (struct ofl_msg_header *)&mod->fm_msg, 0/*xid*/, true/*block*/);
    }

	/* Packet-Out 메시지를 생성하여 수신 패킷을 전송 */
    /* Send out packet if necessary. */
    if (!setup_flows || out_port == -1 || in->buffer_id == UINT32_MAX) {
        if (in->buffer_id == UINT32_MAX) {
            if (in->total_len != in->data_length) {
                /* Control path didn't buffer the packet and didn't send us
                 * the whole thing--what gives? */
                VLOG_DBG(log, "total_len=%"PRIu16" data_len=%zu\n",
                        in->total_len, in->data_length);
                return CONTINUE;
            }
            send_openflow_pkt(pi.dpid, Nonowning_buffer(in->data, in->data_length), in_port, out_port == -1 ? OFPP_FLOOD : out_port, true/*block*/);
        } else {
            send_openflow_pkt(pi.dpid, in->buffer_id, in_port, out_port == -1 ? OFPP_FLOOD : out_port, true/*block*/);
        }
    }
    return CONTINUE;
}


Disposition
Switch::flow_stats_reply_handler(const Event & e)
{
	const Ofp_msg_event& flow_stats_reply = assert_cast<const Ofp_msg_event&>(e);
    struct ofl_msg_multipart_reply_flow *reply_flow = (struct ofl_msg_multipart_reply_flow *)**flow_stats_reply.msg;

	for(int i=0; i < reply_flow->stats_num; i++) 
	{
		int flow_num = i+1;
		uint32_t duration = reply_flow->stats[i]->duration_sec;
		uint64_t cntPkt = reply_flow->stats[i]->packet_count;
		uint64_t cntByt = reply_flow->stats[i]->byte_count;
		cout<< "datapath	" << "flow		" << "duration	" << "packets		" << "bytes	" <<endl;
		cout<< "------------	" << "------------	" << "------------	" << "------------	" << "------------	" <<endl;
		cout<< flow_stats_reply.dpid << "	" << flow_num << "		" << duration << "sec		" << cntPkt << "		" << cntByt <<endl;
		cout<<endl;
	}

	return CONTINUE;
}

Disposition
Switch::aggregate_stats_reply_handler(const Event & e)
{
	const Ofp_msg_event& aggregate_stats_reply = assert_cast<const Ofp_msg_event&>(e);
    struct ofl_msg_multipart_reply_aggregate *reply_aggregate = (struct ofl_msg_multipart_reply_aggregate *)**aggregate_stats_reply.msg;

	uint64_t cntPkt = reply_aggregate->packet_count;
	uint64_t cntByt = reply_aggregate->byte_count;
	uint32_t cntFlw = reply_aggregate->flow_count;

	cout<< "datapath: " << aggregate_stats_reply.dpid << "	packets: " << cntPkt <<" bytes: "  << cntByt << " flows: " << cntFlw <<endl;
	cout<<endl;

	return CONTINUE;
}


void
Switch::monitor()
{
	if(dp[0].as_host() != 0 ) {
		//request_flow_stats(dp[0]);
		request_aggregate_stats(dp[0]);
	}

	tv.tv_sec = 5;
	post(boost::bind(&Switch::monitor, this), tv);

}


void 
Switch::request_flow_stats(const datapathid& dpid)
{
	printf("sending request to switch %d\n", dpid.as_host());

	/* Struct ofp_multipart_request */
	struct ofl_msg_multipart_request_flow req;
	req.header.header.type=OFPT_MULTIPART_REQUEST;
	req.header.type=OFPMP_FLOW;
	req.header.flags=0;

	/* Body for ofp_multipart_request of type OFPMP_FLOW */
	req.table_id=OFPTT_ALL;
	req.out_port=OFPP_ANY;
	req.out_group=OFPG_ANY;
	req.cookie=0;
	req.cookie_mask=0;
	/* Set an empty match */
	Flow  *f = new Flow();
	Actions *acts = new Actions();
	acts->CreateOutput(OFPP_CONTROLLER);
	Instruction *inst =  new Instruction();
	inst->CreateApply(acts);

	req.match = &f->match.header;
	send_openflow_msg(dpid, (struct ofl_msg_header *)&req, 0/*xid*/, true/*block*/);
}

void 
Switch::request_aggregate_stats(const datapathid& dpid)
{
	printf("sending request to switch %d\n", dpid.as_host());

	/* Struct ofp_multipart_request */
	struct ofl_msg_multipart_request_flow req;
	req.header.header.type=OFPT_MULTIPART_REQUEST;
	req.header.type=OFPMP_AGGREGATE;
	req.header.flags=0;

	/* Body for ofp_multipart_request of type OFPMP_AGGREGATE */
	req.table_id=OFPTT_ALL;
	req.out_port=OFPP_ANY;
	req.out_group=OFPG_ANY;
	req.cookie=0;
	req.cookie_mask=0;
	/* Set an empty match */
	Flow  *f = new Flow();
	Actions *acts = new Actions();
	acts->CreateOutput(OFPP_CONTROLLER);
	Instruction *inst =  new Instruction();
	inst->CreateApply(acts);

	req.match = &f->match.header;
	send_openflow_msg(dpid, (struct ofl_msg_header *)&req, 0/*xid*/, true/*block*/);
}


REGISTER_COMPONENT(container::Simple_component_factory<Switch>, Switch);

} // unnamed namespacennamed namespace
