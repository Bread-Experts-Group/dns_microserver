package org.bread_experts_group.dns_microserver

import org.bread_experts_group.Flag
import org.bread_experts_group.logging.ColoredLogger
import org.bread_experts_group.readArgs
import org.bread_experts_group.stream.read16ui
import org.bread_experts_group.stream.write16
import org.bread_experts_group.stringToInt
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.ServerSocket

fun main(args: Array<String>) {
	val logger = ColoredLogger.newLogger("DNS Main")
	logger.fine("- Argument read")
	val (singleArgs, _) = readArgs(
		args,
		"dns_microserver",
		"Distribution of software for Bread Experts Group resolver/name servers for DNS.",
		Flag(
			"ip",
			"The IP address on which to serve DNS queries.",
			default = "0.0.0.0"
		),
		Flag(
			"port",
			"The TCP / UDP port on which to serve DNS queries on.",
			default = 53, conv = ::stringToInt
		),
		Flag<String>(
			"records",
			"The DNS records to serve for each domain; structure: <TLD>/<domain>/[@ | subdomain].<TYPE>",
			required = 1
		),
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
			Thread.currentThread().name = "DNS-UDP"
			try {
				val packet = DatagramPacket(ByteArray(65000), 65000)
				udpSocket.receive(packet)
				Thread.currentThread().name = "UDP-${packet.socketAddress}"
				val localLogger = ColoredLogger.newLogger("DNS UDP ${packet.socketAddress}")
				val reply = dnsExecution(localLogger, recordStore, packet.data, 512)
				if (reply != null) {
					packet.setData(reply)
					udpSocket.send(packet)
				}
			} catch (e: Exception) {
				logger.severe { "UDP FAIL. ${e.stackTraceToString()}" }
			}
		}
	}
	Thread.ofPlatform().name("DNS TCP").start {
		while (true) {
			val socket = tcpSocket.accept()
			Thread.currentThread().name = "DNS-TCP"
			try {
				Thread.currentThread().name = "TCP-${socket.remoteSocketAddress}"
				val localLogger = ColoredLogger.newLogger("DNS TCP ${socket.remoteSocketAddress}")
				val data = socket.inputStream.readNBytes(socket.inputStream.read16ui())
				val reply = dnsExecution(localLogger, recordStore, data)
				if (reply != null) {
					socket.outputStream.write16(reply.size)
					socket.outputStream.write(reply)
				}
			} catch (e: Exception) {
				logger.severe { "TCP FAIL. ${e.stackTraceToString()}" }
				socket.close()
			}
		}
	}
}