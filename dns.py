import socket

ADDRESS = ("8.8.8.8", 53)
ID = 0xCAFE

def make_question_header(params: int, questions: int, answers: int):
    return [ID>>8, ID&0x00ff,
            params>>8, params&0x00ff,
            questions>>8, questions&0x00ff,
            answers>>8, answers&0x00ff,
            0, 0,
            0, 0]

def make_question(address: str, qtype: int = 1, qclass: int = 1):
    parsed = address.split(".")
    hdr = []

    for i in parsed:
        hdr.append(len(i))
        for n in i:
            hdr.append(ord(n))

    hdr.append(0x00)
    
    hdr.extend([qtype>>8, qtype&0x00ff])
    hdr.extend([qclass>>8, qclass&0x00ff])

    return hdr

def send_question(address):
    data = make_question_header(0x0100, 1, 0)
    data += make_question(address)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(ADDRESS)
    sock.send(bytes(data))

    final = sock.recv(2048)
    sock.close()

    return final

def b2i(b: bytes):
    return int.from_bytes(b, "big")

def parse_answer(answer: bytes):
    newID = answer[0:2]
    flags = answer[2:4]
    questions = answer[4:6]
    answers = answer[6:8]
    uservs =  answer[8:10]
    additional_records = answer[10:12]

    newID, flags, questions = b2i(newID), b2i(flags), b2i(questions)
    answers, uservs, additional_records = b2i(answers), b2i(uservs), b2i(additional_records)

    answer_section = answer[12:]
    address = []

    idx = 0
    while answer_section[idx]!=0:
        l = answer_section[idx]
        idx += 1
        address.append(answer_section[idx:l+idx])
        idx += l
    idx += 1

    address = (b'.'.join(address)).decode("utf-8")
    answer_section = answer_section[idx:]

    qtype, qclass = b2i(answer_section[0:2]), b2i(answer_section[2:4])
    answer_section = answer_section[4:]

    wname = answer_section[0:2]
    answer_section = answer_section[6:]

    ttl = b2i(answer_section[0:4])
    rdlength = b2i(answer_section[4:6])

    answer_section = answer_section[6:]

    ip = []

    for i in range(rdlength):
        ip.append(answer_section[i])
    
    return (address, newID, flags, questions, answers, uservs, additional_records,
            qtype, qclass, wname, ttl, rdlength, tuple(ip))

def main():
    answ = send_question("example.com")
    parsed = parse_answer(answ)

    ip = parsed[-1]

    print(f"IP of {parsed[0]}: {'.'.join(map(str, ip))}")

if __name__=="__main__":
    main()
