package bread_experts_group

import bread_experts_group.dns.DNSClass
import bread_experts_group.dns.DNSResourceRecord
import bread_experts_group.dns.DNSType
import bread_experts_group.dns.https.HTTPSParameters
import bread_experts_group.dns.ssh.SSHAlgorithm
import bread_experts_group.dns.ssh.SSHType
import bread_experts_group.dns.writeLabel
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.Inet4Address

fun getAnswerFromFile(name: String, file: File): DNSResourceRecord {
	val stream = file.inputStream()
	val ttl = stream.scanDelimiter("\n").toInt()
	val data = when (file.extension) {
		"CAA" -> ByteArrayOutputStream().use {
			it.write(0)
			val tag = stream.scanDelimiter(" ")
			it.write(tag.length)
			it.writeString(tag)
			it.writeString(stream.readAllBytes().decodeToString().trim())
			it.toByteArray()
		}

		"MX" -> ByteArrayOutputStream().use {
			it.write16(stream.scanDelimiter("\n").toInt())
			it.write(writeLabel(stream.readAllBytes().decodeToString().trim()))
			it.toByteArray()
		}

		"SOA" -> ByteArrayOutputStream().use {
			it.write(writeLabel(stream.scanDelimiter("\n")))
			it.write(writeLabel(stream.scanDelimiter("\n")))
			it.write32(stream.scanDelimiter("\n").toInt())
			it.write32(stream.scanDelimiter("\n").toInt())
			it.write32(stream.scanDelimiter("\n").toInt())
			it.write32(stream.scanDelimiter("\n").toInt())
			it.write32(stream.readAllBytes().decodeToString().trim().toInt())
			it.toByteArray()
		}

		"SSHFP" -> ByteArrayOutputStream().use {
			it.write(SSHAlgorithm.valueOf(stream.scanDelimiter("\n")).code)
			it.write(SSHType.valueOf(stream.scanDelimiter("\n")).code)
			it.writeString(stream.readAllBytes().decodeToString().trim())
			it.toByteArray()
		}

		"HTTPS" -> ByteArrayOutputStream().use {
			it.write16(stream.scanDelimiter("\n").toInt())
			it.write(writeLabel(stream.scanDelimiter("\n")))
			while (stream.available() > 0) {
				val parameter = HTTPSParameters.valueOf(stream.scanDelimiter("\n"))
				it.write16(parameter.code)
				when (parameter) {
					HTTPSParameters.MANDATORY -> {
						val mandatory = stream.scanDelimiter("\n").split(',')
						it.write16(mandatory.size * 2)
						mandatory.forEach { key -> it.write16(HTTPSParameters.valueOf(key).code) }
					}

					HTTPSParameters.ADDITIONAL_SUPPORTED_PROTOCOLS -> {
						val alpns = stream.scanDelimiter("\n").split(',')
						it.write16(alpns.sumOf { it.length } + alpns.size)
						alpns.forEach { alpn ->
							it.write(alpn.length)
							it.writeString(alpn)
						}
					}

					else -> throw UnsupportedOperationException("Unsupported HTTP parameter: $parameter")
				}
			}
			it.toByteArray()
		}

		"HINFO" -> ByteArrayOutputStream().use {
			val cpu = stream.scanDelimiter("\n")
			it.write(cpu.length)
			it.writeString(cpu)
			val remainder = stream.readAllBytes().decodeToString().trim()
			it.write(remainder.length)
			it.writeString(remainder)
			it.toByteArray()
		}

		else -> {
			val remainder = stream.readAllBytes().decodeToString().trim()
			when (file.extension) {
				"A" -> Inet4Address.getByName(remainder).address
				"NS", "PTR", "CNAME" -> writeLabel(remainder)
				"TXT" -> ByteArrayOutputStream().use {
					it.write(remainder.length)
					it.writeString(remainder)
					it.toByteArray()
				}

				else -> throw UnsupportedOperationException(file.extension)
			}
		}
	}
	stream.close()
	return DNSResourceRecord(
		name,
		DNSType.nameMapping.getValue(file.extension),
		DNSClass.IN__INTERNET,
		DNSClass.IN__INTERNET.code,
		ttl, data
	)
}