package bread_experts_group

import org.bread_experts_group.dns.DNSClass
import org.bread_experts_group.dns.DNSResourceRecord
import org.bread_experts_group.dns.DNSType
import org.bread_experts_group.dns.https.HTTPSParameters
import org.bread_experts_group.dns.ssh.SSHAlgorithm
import org.bread_experts_group.dns.ssh.SSHType
import org.bread_experts_group.dns.writeLabel
import org.bread_experts_group.socket.scanDelimiter
import org.bread_experts_group.socket.write16
import org.bread_experts_group.socket.write32
import org.bread_experts_group.socket.writeString
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileReader
import java.net.Inet4Address

fun getAnswerFromFile(name: String, file: File): DNSResourceRecord = FileReader(file).use {
	val ttl = it.scanDelimiter("\n").toLong()
	val data = when (file.extension) {
		"CAA" -> ByteArrayOutputStream().use { d ->
			d.write(0)
			val tag = it.scanDelimiter(" ")
			d.write(tag.length)
			d.writeString(tag)
			d.writeString(it.readText().trim())
			d.toByteArray()
		}

		"MX" -> ByteArrayOutputStream().use { d ->
			d.write16(it.scanDelimiter("\n").toInt())
			d.write(writeLabel(it.readText().trim()))
			d.toByteArray()
		}

		"SOA" -> ByteArrayOutputStream().use { d ->
			d.write(writeLabel(it.scanDelimiter("\n")))
			d.write(writeLabel(it.scanDelimiter("\n")))
			d.write32(it.scanDelimiter("\n").toInt())
			d.write32(it.scanDelimiter("\n").toInt())
			d.write32(it.scanDelimiter("\n").toInt())
			d.write32(it.scanDelimiter("\n").toInt())
			d.write32(it.readText().trim().toInt())
			d.toByteArray()
		}

		"SSHFP" -> ByteArrayOutputStream().use { d ->
			d.write(SSHAlgorithm.valueOf(it.scanDelimiter("\n")).code)
			d.write(SSHType.valueOf(it.scanDelimiter("\n")).code)
			d.write(
				(it.readText().trim())
					.chunked(2)
					.map { c -> c.toInt(16).toByte() }
					.toByteArray()
			)
			d.toByteArray()
		}

		"HTTPS" -> ByteArrayOutputStream().use { d ->
			d.write16(it.scanDelimiter("\n").toInt())
			d.write(writeLabel(it.scanDelimiter("\n")))
			while (it.ready()) {
				val parameter = HTTPSParameters.valueOf(it.scanDelimiter("\n"))
				d.write16(parameter.code)
				when (parameter) {
					HTTPSParameters.MANDATORY -> {
						val mandatory = it.scanDelimiter("\n").split(',')
						d.write16(mandatory.size * 2)
						mandatory.forEach { key -> d.write16(HTTPSParameters.valueOf(key).code) }
					}

					HTTPSParameters.ADDITIONAL_SUPPORTED_PROTOCOLS -> {
						val alpns = it.scanDelimiter("\n").split(',')
						d.write16(alpns.sumOf { a -> a.length } + alpns.size)
						alpns.forEach { alpn ->
							d.write(alpn.length)
							d.writeString(alpn)
						}
					}

					else -> throw UnsupportedOperationException("Unsupported HTTP parameter: $parameter")
				}
			}
			d.toByteArray()
		}

		"HINFO" -> ByteArrayOutputStream().use { d ->
			val cpu = it.scanDelimiter("\n")
			d.write(cpu.length)
			d.writeString(cpu)
			val remainder = it.readText().trim()
			d.write(remainder.length)
			d.writeString(remainder)
			d.toByteArray()
		}

		else -> {
			val remainder = it.readText().trim()
			when (file.extension) {
				"A" -> Inet4Address.getByName(remainder).address
				"NS", "PTR", "CNAME" -> writeLabel(remainder)
				"TXT" -> ByteArrayOutputStream().use { d ->
					d.write(remainder.length)
					d.writeString(remainder)
					d.toByteArray()
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