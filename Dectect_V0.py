from scapy.all import ARP, Ether, sniff, send, get_if_hwaddr, conf, srp, get_if_list
import subprocess
import re
import logging
import sys
import time

# Thiết lập logging
logging.basicConfig(
    filename="arp_stealth.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def get_gateway_ip(iface=None):
    """Lay Dia Chi IP cua Default Gateway Tu ipconfig Hoac route print."""
    try:
        # Thử với ipconfig
        result = subprocess.check_output("ipconfig", shell=True, text=True)
        match = re.search(r"(Default Gateway|Cong Mac Dinh|Gateway Mac Dinh)[ .:]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", result, re.IGNORECASE)
        if match:
            gateway_ip = match.group(2)
            logging.info(f"Gateway IP tu ipconfig: {gateway_ip}")
            return gateway_ip
        
        # Thử với route print nếu ipconfig thất bại
        result = subprocess.check_output("route print", shell=True, text=True)
        match = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", result)
        if match:
            gateway_ip = match.group(1)
            logging.info(f"Gateway IP tu route print: {gateway_ip}")
            return gateway_ip
        
        logging.error("Khong Tim Thay Default Gateway trong ipconfig hoac route print")
    except Exception as e:
        logging.error(f"Loi khi lay Gateway IP: {e}")
    return None

def get_mac(ip, iface):
    """Lay Dia Chi MAC cua IP Muc tieu."""
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
        ans, _ = srp(pkt, timeout=5, verbose=0, iface=iface)
        for _, rcv in ans:
            mac = rcv[Ether].src
            logging.info(f"MAC cua {ip}: {mac}")
            return mac
        logging.warning(f"Khong nhan duoc MAC cho {ip}")
    except Exception as e:
        logging.error(f"Loi Khi Lay MAC cua {ip}: {e}")
    return None

def arp_filter(pkt, my_ip, my_mac, router_ip, router_mac):
    """Loc Va Phan Hoi Chi cac yeu cau ARP tu router."""
    try:
        if pkt.haslayer(ARP) and pkt[ARP].op == 1:  # who-has (request)
            if pkt[ARP].pdst == my_ip:
                sender_ip = pkt[ARP].psrc
                sender_mac = pkt[ARP].hwsrc
                logging.debug(f"Nhan ARP request tu {sender_ip} ({sender_mac}) cho {my_ip}")
                if sender_ip == router_ip and sender_mac.lower() == router_mac.lower():
                    arp_reply = ARP(
                        op=2,
                        hwsrc=my_mac,
                        psrc=my_ip,
                        hwdst=sender_mac,
                        pdst=sender_ip
                    )
                    send(arp_reply, verbose=0, iface=conf.iface)
                    logging.info(f"Da Gui ARP reply den router {router_ip}")
                else:
                    logging.debug(f"Bo qua ARP request tu {sender_ip} (Khong phai router)")
    except Exception as e:
        logging.error(f"Loi trong arp_filter: {e}")

def main():
    # Lấy giao diện mạng từ tham số dòng lệnh
    if len(sys.argv) > 1:
        conf.iface = sys.argv[1]
    else:
        logging.warning("Khong chi dinh giao dien mang, su dung mac dinh")
    
    logging.info(f"Su dung giao dien mang: {conf.iface}")

    # Liệt kê các giao diện mạng để debug
    try:
        interfaces = get_if_list()
        logging.info(f"Danh sach giao dien mang: {interfaces}")
    except Exception as e:
        logging.error(f"Loi khi liet ke giao dien mang: {e}")

    # Lấy IP và MAC của máy
    try:
        my_ip = conf.route.route("0.0.0.0")[1]
        my_mac = get_if_hwaddr(conf.iface)
        logging.info(f"IP cua may: {my_ip}, MAC: {my_mac}")
    except Exception as e:
        logging.error(f"Loi khi lay IP/MAC cua may: {e}")
        sys.exit(1)

    # Lấy IP và MAC của router
    router_ip = get_gateway_ip()
    if not router_ip:
        logging.error("Khong the lay IP của router. Vui long kiem tra ket noi mang hoac chi dinh thu cong.")
        sys.exit(1)

    router_mac = get_mac(router_ip, conf.iface)
    if not router_mac:
        logging.error("Khong the lay MAC cua router. Vui long kiem tra router hoac mang.")
        sys.exit(1)

    # Bắt dầu lọc ARP
    logging.info("Bat dau loc ARP, chi phan hoi cho router...")
    try:
        sniff(filter="arp", prn=lambda pkt: arp_filter(pkt, my_ip, my_mac, router_ip, router_mac), store=0, iface=conf.iface)
    except Exception as e:
        logging.error(f"Loi khi sniff ARP: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
