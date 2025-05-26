package org.bread_experts_group.dns_microserver

import org.bread_experts_group.dns.DNSLabelLiteral
import org.bread_experts_group.dns.DNSMessage
import org.bread_experts_group.dns.DNSOpcode
import org.bread_experts_group.dns.DNSResourceRecord
import org.bread_experts_group.dns.DNSResponseCode
import org.bread_experts_group.dns.DNSType
import org.bread_experts_group.dns.opt.DNSOptionRecord
import org.bread_experts_group.stream.scanDelimiter
import java.io.ByteArrayInputStream
import java.io.File
import java.util.logging.Logger

fun dnsExecution(logger: Logger, recordStore: File, data: ByteArray, maxLength: Int? = null): ByteArray {
	val message = DNSMessage.read(ByteArrayInputStream(data))
	logger.fine { "> $message" }
	val opt = message.additionalRecords.firstNotNullOfOrNull {
		if (it.rrType == DNSType.OPT__OPTION) it as DNSOptionRecord
		else null
	}
	val (maxLength, additional) = if (opt != null) opt.dnsPayloadSize to listOf(DNSOptionRecord(opt.dnsPayloadSize))
	else maxLength to emptyList<DNSResourceRecord>()
	val error = if (message.opcode != DNSOpcode.QUERY) DNSMessage.reply(
		message, maxLength,
		authoritative = true, authenticData = false, recursionAvailable = false,
		DNSResponseCode.NOT_IMPLEMENTED,
		emptyList()
	) else if (
		message.reply || message.questions.isEmpty() ||
		message.questions.any { it.name !is DNSLabelLiteral } ||
		(opt != null && opt.eDNSVersion != 0)
	) DNSMessage.reply(
		message, maxLength,
		authoritative = true, authenticData = false, recursionAvailable = false,
		DNSResponseCode.FORMAT_ERROR,
		emptyList()
	) else null
	if (error != null) {
		logger.fine { "Bad DNS message!" }
		logger.fine { "< $error" }
		return error.asBytes()
	}
	val answers = mutableListOf<DNSResourceRecord>()
	for (question in message.questions) {
		var thisRecord = recordStore
		val pathParts = (question.name as DNSLabelLiteral).literal
			.lowercase()
			.split('.')
			.filter(String::isNotEmpty)
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
						(question.qType != DNSType.ALL_RECORDS && question.qType != DNSType.CNAME__CANONICAL_NAME)
						&& it.extension == "CNAME"
					) {
						val reference = it.inputStream().use { s ->
							s.scanDelimiter("\n")
							s.readAllBytes().decodeToString().trim()
								.lowercase()
								.split('.')
								.filter(String::isNotEmpty)
						}
						addAnswers(reference.take(reference.size - 2).joinToString("."))
					} else answers.add(getAnswerFromFile(question.name, it))
				}
			}
		}
		addAnswers(localPath)
	}
	val reply = DNSMessage.reply(
		message, maxLength,
		authoritative = true, authenticData = false, recursionAvailable = false,
		DNSResponseCode.OK,
		answers, additionalRecords = additional
	)
	logger.fine { "< $reply" }
	return reply.asBytes()
}