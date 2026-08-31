package com.islam24.api.service

import com.islam24.api.entity.RefreshToken
import com.islam24.api.entity.User
import com.islam24.api.repository.RefreshTokenRepository
import com.islam24.api.security.hashToken
import org.springframework.stereotype.Service
import java.time.Instant
import java.util.UUID

@Service
class RefreshTokenService(private val refreshTokenRepository: RefreshTokenRepository) {

    fun create(user: User): String {
        val rawToken = UUID.randomUUID().toString()
        val hashToken = hashToken(token = rawToken)

        // Long-lived device session (365 days / 1 year) like YouTube, Spotify, and Telegram
        val defaultExpiryMillis = 365L * 24 * 60 * 60 * 1000L
        val expiryMillis = System.getenv("REFRESH_EXPIRE_MILI")?.toLongOrNull() ?: defaultExpiryMillis

        val refreshToken = RefreshToken(
            tokenHash = hashToken,
            user = user,
            expiresAt = Instant.now().plusMillis(expiryMillis),
        )
        refreshTokenRepository.save(refreshToken)
        return rawToken
    }

}