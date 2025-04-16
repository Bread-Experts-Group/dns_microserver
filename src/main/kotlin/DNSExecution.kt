package bread_experts_group

import bread_experts_group.dns.DNSMessage
import bread_experts_group.dns.DNSOpcode
import bread_experts_group.dns.DNSResourceRecord
import bread_experts_group.dns.DNSResponseCode
import bread_experts_group.dns.DNSType
import java.io.ByteArrayInputStream
import java.io.File
import java.util.logging.Logger

fun dnsExecution(logger: Logger, recordStore: File, data: ByteArray, maxLength: Int? = null): ByteArray? {
	try {
		val message = DNSMessage.read(ByteArrayInputStream(data))
		if (message.reply || message.questions.isEmpty()) return null
		logger.finer("> $message")
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
					it.extension == question.qType.name.substringBefore("__") || it.name == "$localPath.CNAME"
				}
			if (records.isNullOrEmpty()) continue
			fun addAnswers(lookingFor: String) {
				records.forEach {
					if (
						(lookingFor.isEmpty() && it.name.startsWith('@', true)) ||
						(lookingFor.isNotEmpty() && it.name.startsWith(lookingFor, true))
					) {
						if (
							(question.qType != DNSType.ALL_RECORDS && question.qType != DNSType.CNAME__CANONICAL_NAME) &&
							it.extension == "CNAME"
						) {
							val stream = it.inputStream()
							stream.scanDelimiter("\n")
							val reference = stream.readAllBytes().decodeToString()
								.trim().lowercase().split('.').filter(String::isNotEmpty)
							stream.close()
							addAnswers(reference.take(reference.size - 2).joinToString("."))
						} else answers.add(getAnswerFromFile(question.name, it))
					}
				}
			}
			addAnswers(localPath)
		}
		val reply = DNSMessage.reply(
			message.transactionID, maxLength, DNSOpcode.QUERY,
			true, false, false,
			DNSResponseCode.OK,
			message.questions, answers
		)
		logger.finer("< $reply")
		return reply.asBytes()
	} catch (e: Exception) {
		logger.severe { "FAIL. ${e.stackTraceToString()}" }
	}
	return null
}