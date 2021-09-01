import socket
import random

__all__ = ['Tracer']

class Tracer(object):
    def __init__(self, dst, hops=100):
        """
        Inicializa um novo objeto rastreador

        Args:
            dst (str): host de destino para sondar
            hops (int): Número máximo de saltos para sondar
        """
        self.dst = dst
        self.hops = hops
        self.ttl = 1

        ##Pegue uma porta aleatória no intervalo 33434-33534
        self.port = random.choice(range(33434, 33535))

    def run(self):
        """
        Executar o tracer
        Raises:
            IOError
        """
        try:
            dst_ip = socket.gethostbyname(self.dst)
        except socket.error as e:
            raise IOError('Unable to resolve {}: {}', self.dst, e)

        text = 'traceroute to {} ({}), {} hops max'.format(
            self.dst,
            dst_ip,
            self.hops
        )

        print(text)

        while True:
            receiver = self.create_receiver() 
            sender = self.create_sender()
            sender.sendto(b'', (self.dst, self.port))

            addr = None
            try:
                data, addr = receiver.recvfrom(1024)
            except socket.error:
                raise IOError('Socket error: {}'.format(e))
            finally:
                receiver.close()                
                sender.close()

            if addr:
                print('{:<4} {}'.format(self.ttl, addr[0]))
            else:
                print('{:<4} *'.format(self.ttl))

            self.ttl += 1

            if addr[0] == dst_ip or self.ttl > self.hops:
                break

    def create_receiver(self):
        """
        Cria um soquete de receptor
        return: uma instância de soquete

        Raises:
            IOError
        """
        s = socket.socket(
            family=socket.AF_INET,
            type=socket.SOCK_RAW,
            proto=socket.IPPROTO_ICMP
        )

        try:
            s.bind(('', self.port))
        except socket.error as e:
            raise IOError('Unable to bind receiver socket: {}'.format(e))

        return s

    def create_sender(self):
        """
        Cria um soquete de remetente
        return: uma instância de soquete
        """
        s = socket.socket(
            family=socket.AF_INET,
            type=socket.SOCK_DGRAM,
            proto=socket.IPPROTO_UDP
        )

        s.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)

        return s