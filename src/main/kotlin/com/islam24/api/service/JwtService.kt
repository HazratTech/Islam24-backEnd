package com.islam24.api.service

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.springframework.stereotype.Service
import java.util.Date
import java.util.UUID
import javax.crypto.SecretKey
import javax.xml.crypto.Data


@Service
class JwtService {

    private val secretKey: SecretKey = Keys.hmacShaKeyFor(System.getenv("JWT_SECRET").toByteArray())

    fun generateAccessToken(userId: UUID): String {
        val defaultExpirationMillis = 24L * 60 * 60 * 1000L // 24 hours
        val expirationMillis = System.getenv("JWT_EXPIRATION")?.toLongOrNull() ?: defaultExpirationMillis

        return Jwts.builder()
            .subject(userId.toString())
            .issuedAt(Date())
            .expiration(
                Date(System.currentTimeMillis() + expirationMillis)
            )
            .signWith(secretKey)
            .compact()
    }

    fun extractToken(token: String): UUID {
        val claim = Jwts.parser()
            .verifyWith(secretKey)
            .build()
            .parseSignedClaims(token)

        return UUID.fromString(claim.payload.subject)
    }

}