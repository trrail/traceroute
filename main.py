import argparse

from traceroute import Traceroute

parser = argparse.ArgumentParser()
parser.add_argument('host', type=str, help="Enter hostname, you want to trace")
parser.add_argument("--ttl", type=int, help="Enter max ttl", default=30)


args = parser.parse_args()
traceroute = Traceroute(args.host, args.ttl)
result = traceroute.make_trace()
counter = 1
for i in result:
    print(f'{counter}. {i}')
    counter += 1
