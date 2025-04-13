package bread_experts_group

import bread_experts_group.dns.DNSMessage
import bread_experts_group.dns.DNSOpcode
import bread_experts_group.dns.DNSResourceRecord
import bread_experts_group.dns.DNSResponseCode
import bread_experts_group.dns.DNSType
import java.io.ByteArrayInputStream
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress

fun main(args: Array<String>) {
	Thread.currentThread().name = "DNS-Main"
	debug("- Argument read")
	val (singleArgs, _) = readArgs(
		args,
		Flag<String>("ip", default = "0.0.0.0"),
		Flag<Int>("port", default = 53, conv = ::stringToInt),
		Flag<Int>("verbosity", default = 1, conv = ::stringToInt),
		Flag<String>("records"),
	)
	toStringVerbosity = (singleArgs["verbosity"] as? Int) ?: toStringVerbosity
	debug("- Socket retrieval & bind (${singleArgs["port"]})")
	val udpSocket = DatagramSocket(
		InetSocketAddress(
			singleArgs["ip"] as String,
			singleArgs["port"] as Int
		)
	)
	val recordStore = File(singleArgs.getValue("records") as String).absoluteFile.normalize()
	info("- Server loop (Record Store: $recordStore)")
	Thread.ofPlatform().name("DNS").start {
		while (true) {
			val packet = DatagramPacket(ByteArray(65535), 65535)
			udpSocket.receive(packet)
			Thread.currentThread().name = "DNS-${packet.socketAddress}"
			try {
				val message = DNSMessage.read(ByteArrayInputStream(packet.data))
				if (message.reply || message.questions.isEmpty()) continue
				info("> $message")
				val answers = mutableListOf<DNSResourceRecord>()
				for (question in message.questions) {
					var thisRecord = recordStore
					val pathParts = question.name.lowercase().split('.').filter(String::isNotEmpty)
					if (pathParts.size < 2) continue
					for (path in pathParts.takeLast(2).reversed()) {
						thisRecord = thisRecord.resolve(path)
						if (!thisRecord.exists() || thisRecord.isFile) break
					}
					val localPath = pathParts.take(pathParts.size - 2).joinToString(".")
					val records =
						if (question.qType == DNSType.ALL_RECORDS) thisRecord.listFiles()
						else thisRecord.listFiles {
							it.name.endsWith(question.qType.name.substringBefore("__"), true) ||
									it.name == "$localPath.CNAME"
						}
					if (records.isNullOrEmpty()) continue
					fun addAnswers(lookingFor: String) {
						records.forEach {
							if (
								(lookingFor.isEmpty() && it.name.startsWith('@', true)) ||
								(lookingFor.isNotEmpty() && it.name.startsWith(lookingFor, true))
							) {
								if (it.name.endsWith("CNAME")) {
									val reference = it.readText().substringAfter('\n').trim().split('.')
									addAnswers(reference.take(reference.size - 2).joinToString("."))
								} else answers.add(getAnswerFromFile(question.name, it))
							}
						}
					}
					addAnswers(localPath)
				}
				val reply = DNSMessage.reply(
					message.transactionID, DNSOpcode.QUERY,
					true, false, false,
					DNSResponseCode.OK,
					message.questions, answers
				)
				info("< $reply")
				packet.setData(reply.asBytes())
				udpSocket.send(packet)
			} catch (e: Exception) {
				warn(packet.data.sliceArray(0..packet.length - 1).joinToString(", ") { it.toUByte().toString(16).uppercase().padStart(2, '0') })
				error("FAIL. ${e.stackTraceToString()}")
			}
		}
	}
}