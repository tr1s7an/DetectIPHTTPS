import requests
import re
import ipaddress
from multiprocessing import Pool

# start = 202.81.224.0
ip = "202.81.%d.%d"
# a factor of 32
p = 32
results_dict = {}

headers = {
    "User-Agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0"
}
results_file = "results"


def pre():
    with open(results_file, 'w') as f:
        f.write("*" * 10)
        f.write("\n")


def detect(i):
    res = []
    for j in range(i, i + 1):
        for k in range(0, 256):
            this_ip = ip % (j, k)
            try:
                req = requests.get("https://" + this_ip,
                                   headers=headers,
                                   timeout=2)
                print(this_ip, req.status_code)
            except Exception as e:
                error = str(e)
                if "match" in error:
                    name = re.findall("[^t]\s\'(.+?)\'", error)
                    res.append(name)
    return res


def process(results):
    global results_dict
    for result in results:
        if len(result) > 1:
            results_dict[result[0]] = ' '.join(result[1:])
        else:
            print(result)


def write_to_file(results_dict):
    sorted_keys = sorted(results_dict.keys(), key=ipaddress.IPv4Address)
    with open(results_file, "a") as f:
        for key in sorted_keys:
            f.write(key)
            f.write(" ")
            f.write(results_dict[key])
            f.write("\n")


if __name__ == "__main__":
    pre()
    pool = Pool(p)
    for i in range(224, 256):
        pool.apply_async(func=detect, args=(i, ), callback=process)
    pool.close()
    pool.join()
    write_to_file(results_dict)
