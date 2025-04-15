package bread_experts_group

import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.util.logging.Logger

fun main(args: Array<String>) {
	val logger = Logger.getLogger("DNS Main")
	logger.fine("- Argument read")
	val (singleArgs, _) = readArgs(
		args,
		Flag<String>("ip", default = "0.0.0.0"),
		Flag<Int>("port", default = 53, conv = ::stringToInt),
		Flag<String>("records"),
	)
	logger.fine("- Socket retrieval & bind UDP (${singleArgs["port"]})")
	val udpSocket = DatagramSocket(
		InetSocketAddress(
			singleArgs["ip"] as String,
			singleArgs["port"] as Int
		)
	)
	logger.fine("- Socket retrieval & bind TCP (${singleArgs["port"]})")
	val tcpSocket = ServerSocket()
	tcpSocket.bind(
		InetSocketAddress(
			singleArgs["ip"] as String,
			singleArgs["port"] as Int
		)
	)
	val recordStore = File(singleArgs.getValue("records") as String).absoluteFile.normalize()
	logger.info("- Server loop (Record Store: $recordStore)")
	Thread.ofPlatform().name("DNS UDP").start {
		while (true) {
			val packet = DatagramPacket(ByteArray(65535), 65535)
			udpSocket.receive(packet)
			Thread.currentThread().name = "DNS-${packet.socketAddress}"
			val localLogger = Logger.getLogger("DNS UDP ${packet.socketAddress}")
			val reply = dnsExecution(localLogger, recordStore, packet.data)
			if (reply != null) {
				packet.setData(reply)
				udpSocket.send(packet)
			}
		}
	}
	Thread.ofPlatform().name("DNS TCP").start {
		while (true) {
			val socket = tcpSocket.accept()
			Thread.currentThread().name = "TCP-${socket.remoteSocketAddress}"
			val localLogger = Logger.getLogger("DNS TCP ${socket.remoteSocketAddress}")
			val data = socket.inputStream.readNBytes(socket.inputStream.read16().toUShort().toInt())
			val reply = dnsExecution(localLogger, recordStore, data)
			if (reply != null) {
				socket.outputStream.write16(reply.size)
				socket.outputStream.write(reply)
			}
		}
	}
}