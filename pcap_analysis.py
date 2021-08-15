import sys
import pyshark

filename = sys.argv[1]

capfile1 = pyshark.FileCapture(filename, only_summaries=True)
capfile1.load_packets()
pck1_count = len(capfile1)	

capfile2 = pyshark.FileCapture(filename)
capfile2.load_packets()
pck2_count = len(capfile2)


def packet_info():
	pck_req = 0
	pck_recv = 0
	
	for e in range(pck1_count):
		pack = capfile2[e].icmp.type
		protocol = capfile1[e].protocol
		
		if protocol == "ICMP":	
			if pack == "8":
				pck_req = pck_req + 1

			elif pack == "0":
				pck_recv = pck_recv + 1
			else:
				continue
		total_icmp = pck_req + pck_recv
	
	print("Total {0} packets captured: {1}".format(protocol, total_icmp))
	print("\t {0} packets request: {1}".format(protocol, pck_req))
	print("\t {0} packets reply: {1}".format(protocol, pck_recv))
 
def throughput():
	total_size = 0
	
	for i in range(pck1_count):
		packet = capfile1[i]
		dt_size = int(packet.length)
		total_size = total_size + dt_size
		
		delta_time = float(capfile1[i].time) - float(capfile1[0].time)
		
	avg_tput = round((total_size / delta_time), 2)
	print("Throughput: {} Bytes/second".format(avg_tput))

def latency():
	total_resptime = 0
		
	for i in range(pck2_count):
		idx_mod = i%2
		
		if idx_mod !=0:
			rsp_time = capfile2[i].icmp.resptime
			new_rsp_time = rsp_time.replace(",",".")
			total_resptime = total_resptime + round(float(new_rsp_time),3)
			
	avg_latency = round(total_resptime/(pck2_count/2),3)
	print("Average Latency: {} msec".format(avg_latency))	

def jitter():
	array_resptime = []
	rsp_time = 0
	
	for x in range(pck2_count):
		idx_mod = x%2
		
		if idx_mod !=0:
			rsp_time = capfile2[x].icmp.resptime
			new_rsp_time = rsp_time.replace(",",".")
			array_resptime.append(new_rsp_time)
	
	total_diff = 0
	
	for y in range(len(array_resptime)-1):
		a = float(array_resptime[y])
		b = float(array_resptime[y+1])
		
		delta_latency = round((b - a), 3)
		
		total_diff = total_diff + abs(delta_latency)

	avg_jitter = round((total_diff / (len(array_resptime)-1)), 3)
	print("Average Jitter: {} msec".format(avg_jitter))

def e2e_delay():
	
	time_delta = 0
	src = capfile2[0].ip.src
	dst = capfile2[0].ip.dst
	
	pck_req = 0
	
	for r in range(pck2_count):
		pck_msg = capfile2[r].icmp.type
		
		if pck_msg == "8":
			pck_delta = capfile2[r].frame_info.time_delta
			time_delta = time_delta + round(float(pck_delta),3)			
			pck_req += 1
		else:
			continue
		
	avg_delay = (time_delta*1000)/pck2_count
	
	print("\nPacket sent from {0} to {1}: {2}".format(src, dst, pck_req))
	print("Average End-to-End Delay: {} msec".format(avg_delay))
	
packet_info()
throughput()
latency()
jitter()
e2e_delay()

