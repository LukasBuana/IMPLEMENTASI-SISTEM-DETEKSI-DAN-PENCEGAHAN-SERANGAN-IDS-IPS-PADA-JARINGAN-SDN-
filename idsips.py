from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp
from ryu.lib import hub
import time

class SynFloodIPS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Konfigurasi deteksi
    SYN_FLOOD_THRESHOLD = 50     # Ambang batas SYN flood awal (misal: 3 SYN dalam TIME_WINDOW)
    RE_BLOCK_THRESHOLD = 50      # Ambang batas SYN flood untuk IP yang pernah diblokir (misal: 1 SYN)
    TIME_WINDOW = 5             # Deteksi dalam 5 detik terakhir
    BLOCK_TIME = 30             # Blokir IP selama 30 detik

    # Prioritas rule OpenFlow
    PRIORITY_DEFAULT = 0
    PRIORITY_MAC_LEARNING = 1
    PRIORITY_SYN_INTERCEPT = 500 # Prioritas baru untuk mencegat paket SYN
    PRIORITY_BLOCK = 1000        # Prioritas untuk rule drop

    def __init__(self, *args, **kwargs):
        super(SynFloodIPS, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.syn_records = {}       # Menyimpan timestamp SYN per IP
        self.blocked_ips = {}       # Menyimpan IP yang sedang diblokir dan waktu berakhir blokir
        self.past_attackers = set() # Menyimpan IP yang pernah diblokir setidaknya sekali

        # Memulai thread monitor untuk menghapus blokir yang sudah kadaluarsa
        self.monitor_thread = hub.spawn(self._block_expiry_monitor)
        self.logger.info("SYN Flood IPS started.")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Menangani event ketika switch terhubung dan mengirimkan fitur-fiturnya.
        Menginstal flow default dan flow untuk mencegat paket SYN ke controller.
        """
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # 1. Flow default: kirim semua paket yang tidak cocok ke controller
        match_default = parser.OFPMatch()
        actions_default = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                                   ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, self.PRIORITY_DEFAULT, match_default, actions_default)
        self.logger.info(f"Switch {datapath.id} connected. Installed default flow (prio {self.PRIORITY_DEFAULT}).")

        # 2. Flow untuk mencegat paket SYN dan mengirimkannya ke controller
        # Ini akan memastikan controller selalu melihat paket SYN, bahkan setelah MAC learning.
        match_syn = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_flags=0x02) # eth_type=IPv4, ip_proto=TCP, tcp_flags=SYN
        actions_syn = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, self.PRIORITY_SYN_INTERCEPT, match_syn, actions_syn)
        self.logger.info(f"Installed SYN intercept flow (prio {self.PRIORITY_SYN_INTERCEPT}).")


    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        """
        Fungsi helper untuk menambahkan flow entry ke switch.
        """
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout)
        datapath.send_msg(mod)
        self.logger.debug(f"Added flow: prio={priority}, match={match}, actions={actions}, idle_t={idle_timeout}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Menangani setiap paket yang masuk ke controller.
        Melakukan pembelajaran MAC dan meneruskan paket, serta memanggil deteksi SYN flood.
        """
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            # Jika bukan paket Ethernet, abaikan
            return

        dst = eth.dst
        src = eth.src

        # Pembelajaran MAC address
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # Tentukan port keluar
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)

        actions = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(in_port=in_port, eth_dst=dst)

        # Jika port tujuan diketahui, tambahkan flow untuk menghindari PacketIn di masa depan
        # Prioritas ini lebih rendah dari SYN_INTERCEPT, sehingga SYN tetap ke controller
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, self.PRIORITY_MAC_LEARNING, match, actions) 

        # Kirim paket ke tujuan (jika buffer_id valid, gunakan buffer_id)
        # Jika paket datang karena SYN_INTERCEPT, mungkin tidak ada buffer_id
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        else:
            data = None # Gunakan buffer_id jika ada

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data) # Kirim data jika tidak ada buffer_id
        datapath.send_msg(out)

        # Cek SYN flood untuk setiap paket TCP
        self.detect_syn_flood(pkt, datapath)

    def detect_syn_flood(self, pkt, datapath):
        """
        Mendeteksi serangan SYN flood berdasarkan ambang batas.
        """
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        # Pastikan paket adalah TCP dan IPv4
        if tcp_pkt and ipv4_pkt:
            # Cek apakah ini paket SYN (SYN flag set, ACK flag not set)
            if tcp_pkt.has_flags(tcp.TCP_SYN) and not tcp_pkt.has_flags(tcp.TCP_ACK):
                src_ip = ipv4_pkt.src
                now = time.time()

                # Hapus catatan SYN yang sudah kadaluarsa dari jendela waktu
                syn_times = self.syn_records.get(src_ip, [])
                syn_times = [t for t in syn_times if now - t < self.TIME_WINDOW]
                syn_times.append(now) # Tambahkan timestamp SYN saat ini
                self.syn_records[src_ip] = syn_times

                self.logger.info(f"Received SYN from {src_ip}. Current count in window: {len(syn_times)}")

                # Tentukan ambang batas yang akan digunakan
                # Jika IP pernah diblokir, gunakan RE_BLOCK_THRESHOLD yang lebih rendah
                current_threshold = self.RE_BLOCK_THRESHOLD if src_ip in self.past_attackers else self.SYN_FLOOD_THRESHOLD
                self.logger.debug(f"IP {src_ip} in past_attackers: {src_ip in self.past_attackers}, current_threshold: {current_threshold}")

                # Jika jumlah SYN melebihi ambang batas dan IP belum diblokir
                # Menggunakan operator '>=' untuk deteksi yang lebih sensitif
                if len(syn_times) >= current_threshold and src_ip not in self.blocked_ips:
                    self.logger.warning(f"*** ALERT: SYN Flood detected from {src_ip} (Count: {len(syn_times)}, Threshold: {current_threshold}) ***")
                    self.block_ip(datapath, src_ip)

    def block_ip(self, datapath, ip):
        """
        Memblokir IP penyerang dengan menambahkan flow drop ke switch.
        """
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Match untuk semua paket dari IP sumber ini
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        actions = []  # Aksi kosong berarti drop paket

        self.logger.info(f"Installing drop rule for IP: {ip} with idle_timeout={self.BLOCK_TIME} seconds.")
        # Tambahkan flow drop dengan idle_timeout
        self.add_flow(datapath, self.PRIORITY_BLOCK, match=match, actions=actions,
                      idle_timeout=self.BLOCK_TIME)

        # Catat IP yang diblokir dan waktu kadaluarsanya
        self.blocked_ips[ip] = time.time() + self.BLOCK_TIME
        # Tambahkan IP ke daftar penyerang yang pernah diblokir
        self.past_attackers.add(ip)
        self.logger.info(f"Blocked IP {ip} for {self.BLOCK_TIME} seconds. Added to past attackers list.")

    def _block_expiry_monitor(self):
        """
        Thread terpisah untuk memantau dan menghapus IP dari daftar blokir
        setelah waktu BLOCK_TIME berakhir.
        """
        self.logger.info("Block expiry monitor started.")
        while True:
            now = time.time()
            expired_ips = [ip for ip, t in self.blocked_ips.items() if now > t]
            for ip in expired_ips:
                del self.blocked_ips[ip]
                # Catatan: syn_records untuk IP ini akan secara alami kosong
                # karena tidak ada paket yang mencapai controller selama blokir.
                # Kita tidak perlu menghapusnya dari past_attackers, karena kita ingin
                # mengingatnya untuk deteksi ulang yang lebih sensitif.
            hub.sleep(1) # Cek setiap 1 detik
