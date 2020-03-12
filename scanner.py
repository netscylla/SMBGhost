import socket
import struct
import sys
import time
import argparse
from netaddr import IPNetwork
import concurrent.futures
try:
    import tqdm
except ModuleNotFoundError:
    tqdm = None

def parse_args():
    parser = argparse.ArgumentParser(
        description="Threaded script to scan for smbv3 vulnerability.")
    parser.add_argument("-r", "--range",
                        help="cidr range to scan.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Display debug messages.")
    parser.add_argument("-t", "--threads", type=int, default=20,
                        help="Number of threads to run with. Default is 20")
    parser.add_argument("-o", "--output", type=argparse.FileType('w'), default=sys.stdout,
                        help="Output file containing one vulnerable domain per line. If omitted, vulnerable domains "
                             "will be output on stdout")
    return parser.parse_args()
	
def progressbar(it, **kwargs):
    if args.verbose or not tqdm:
        return it
    else:
        return tqdm.tqdm(it, **kwargs)

def message(m):
    # Using print() as intended, with the newline in the end argument, somehow breaks in a multi-threaded
    # environment - another thread is able to print something between the message and the newline added by print()
    print("{}\n".format(m), end="", file=sys.stderr, flush=True)
		
def verbose(m):
    if args.verbose:
        message(m)


def error(m):
    if args.verbose:
        message("Error: {}".format(m))



def test_smbv3(ip):

    pkt = b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'


    sock = socket.socket(socket.AF_INET)
    sock.settimeout(3)

    try:
        sock.connect(( str(ip),  445 ))
		
        try:
            sock.send(pkt)
        except socket.timeout:
            error(str(ip)+" Timeout")
        nb, = struct.unpack(">I", sock.recv(4))
        res = sock.recv(nb)

        if res[68:70] != b"\x11\x03" or res[70:72] != b"\x02\x00":
            verbose(f"{ip} Not vulnerable.")
            return(f"{ip} Not Vulnerable")
        else:
            verbose(f"{ip} Vulnerable")
            return(f"{ip} Vulnerable")
		
    except OSError:
        error(str(ip)+":445 not open")
    except:
        sock.close()
    
		

if __name__ == "__main__":
    print("-----------------------------------------------------------")
    print("|                   SMBGhost Scanner                       |")
    print("|                        By Andy                           |")
    print("|                       @netscylla                         |")
    print("|  Based on code from https://github.com/ollypwn/SMBGhost  |")
    print("-----------------------------------------------------------")
    args = parse_args()


    start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor, args.output as out_file:
        for result in progressbar(
                (
                        f.result()
                        for f in
                        concurrent.futures.as_completed(
                            executor.submit(test_smbv3, ip)
                            for ip in
                            IPNetwork(args.range)
                        )
                ),
        ):
            if result:
                out_file.write(result + "\n")
                out_file.flush()
    print("Done!  Total execution time: ", time.perf_counter() - start, " seconds")