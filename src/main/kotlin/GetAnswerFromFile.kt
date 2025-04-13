package bread_experts_group

import bread_experts_group.dns.DNSClass
import bread_experts_group.dns.DNSResourceRecord
import bread_experts_group.dns.DNSType
import bread_experts_group.dns.writeLabel
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.Inet4Address

fun getAnswerFromFile(name: String, file: File): DNSResourceRecord {
	val stream = file.inputStream()
	val ttl = stream.scanDelimiter("\n").toInt()
	val data = when (file.extension) {
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

		else -> {
			val remainder = stream.readAllBytes().decodeToString().trim()
			when (file.extension) {
				"A" -> Inet4Address.getByName(remainder).address
				"NS", "PTR" -> writeLabel(remainder)
				"TXT" -> ByteArrayOutputStream().use {
					it.write(remainder.length)
					it.writeString(remainder)
					it.toByteArray()
				}

				else -> throw UnsupportedOperationException(file.extension)
			}
		}
	}
	return DNSResourceRecord(
		name,
		DNSType.nameMapping.getValue(file.extension),
		DNSClass.IN__INTERNET,
		DNSClass.IN__INTERNET.code,
		ttl, data
	)
}