package org.bread_experts_group.dns_microserver

import org.bread_experts_group.dns.DNSClass
import org.bread_experts_group.dns.DNSLabel
import org.bread_experts_group.dns.DNSResourceRecord
import org.bread_experts_group.dns.DNSType
import org.bread_experts_group.dns.https.HTTPSParameters
import org.bread_experts_group.dns.ssh.SSHAlgorithm
import org.bread_experts_group.dns.ssh.SSHType
import org.bread_experts_group.dns.writeLabel
import org.bread_experts_group.stream.scanDelimiter
import org.bread_experts_group.stream.write16
import org.bread_experts_group.stream.write32
import org.bread_experts_group.stream.writeString
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.net.Inet4Address
import java.net.Inet6Address

fun getAnswerFromFile(name: DNSLabel, file: File): DNSResourceRecord = FileInputStream(file).use {
	fun readRemainder() = it.readAllBytes().decodeToString().trim()

	val ttl = it.scanDelimiter("\n").toLong()
	val data = when (file.extension) {
		"CAA" -> ByteArrayOutputStream().use { d ->
			d.write(0)
			val tag = it.scanDelimiter(" ")
			d.write(tag.length)
			d.writeString(tag)
			d.writeString(readRemainder())
			d.toByteArray()
		}

		"MX" -> ByteArrayOutputStream().use { d ->
			d.write16(it.scanDelimiter("\n").toInt())
			d.write(writeLabel(readRemainder()))
			d.toByteArray()
		}

		"SOA" -> ByteArrayOutputStream().use { d ->
			d.write(writeLabel(it.scanDelimiter("\n")))
			d.write(writeLabel(it.scanDelimiter("\n")))
			d.write32(it.scanDelimiter("\n").toInt())
			d.write32(it.scanDelimiter("\n").toInt())
			d.write32(it.scanDelimiter("\n").toInt())
			d.write32(it.scanDelimiter("\n").toInt())
			d.write32(readRemainder().toInt())
			d.toByteArray()
		}

		"SSHFP" -> ByteArrayOutputStream().use { d ->
			d.write(SSHAlgorithm.valueOf(it.scanDelimiter("\n")).code)
			d.write(SSHType.valueOf(it.scanDelimiter("\n")).code)
			d.write(
				readRemainder()
					.chunked(2)
					.map { c -> c.toInt(16).toByte() }
					.toByteArray()
			)
			d.toByteArray()
		}

		"HTTPS" -> ByteArrayOutputStream().use { d ->
			d.write16(it.scanDelimiter("\n").toInt())
			d.write(writeLabel(it.scanDelimiter("\n")))
			while (it.available() > 0) {
				val parameter = HTTPSParameters.valueOf(it.scanDelimiter("\n"))
				d.write16(parameter.code)
				val svcData = ByteArrayOutputStream()
				when (parameter) {
					HTTPSParameters.MANDATORY -> {
						val mandatory = it.scanDelimiter("\n").split(',')
						mandatory.forEach { key -> svcData.write16(HTTPSParameters.valueOf(key).code) }
					}

					HTTPSParameters.ADDITIONAL_SUPPORTED_PROTOCOLS -> {
						val alpns = it.scanDelimiter("\n").split(',')
						alpns.forEach { alpn ->
							svcData.write(alpn.length)
							svcData.writeString(alpn)
						}
					}

					HTTPSParameters.NO_SUPPORT_FOR_DEFAULT_PROTOCOL -> {}
					HTTPSParameters.ALTERNATIVE_PORT -> d.write16(it.scanDelimiter("\n").toInt())
					HTTPSParameters.IPV4_HINT -> {
						val ips = it.scanDelimiter("\n").split(',')
						ips.forEach { ip -> svcData.write((Inet4Address.getByName(ip) as Inet4Address).address) }
					}

					HTTPSParameters.IPV6_HINT -> {
						val ips = it.scanDelimiter("\n").split(',')
						ips.forEach { ip -> svcData.write((Inet4Address.getByName(ip) as Inet6Address).address) }
					}

					HTTPSParameters.ENCRYPTED_CLIENT_HELLO -> TODO("Encrypted Client Hello configuration")
				}
				d.write16(svcData.size())
				d.write(svcData.toByteArray())
			}
			d.toByteArray()
		}

		"HINFO" -> ByteArrayOutputStream().use { d ->
			val cpu = it.scanDelimiter("\n")
			d.write(cpu.length)
			d.writeString(cpu)
			val remainder = readRemainder()
			d.write(remainder.length)
			d.writeString(remainder)
			d.toByteArray()
		}

		else -> {
			val remainder = readRemainder()
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