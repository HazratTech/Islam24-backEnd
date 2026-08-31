package com.islam24.api.service

import com.islam24.api.dto.auth.AuthRequest
import com.islam24.api.dto.auth.AuthResponse
import com.islam24.api.dto.auth.LogoutRequest
import com.islam24.api.dto.auth.RefreshRequest
import com.islam24.api.dto.auth.RefreshResponse
import com.islam24.api.error.exception.InvalidRefreshTokenException
import com.islam24.api.mapper.toEntity
import com.islam24.api.repository.RefreshTokenRepository
import com.islam24.api.repository.UserRepository
import com.islam24.api.security.hashToken
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Instant
import java.time.LocalDateTime
import java.util.Date


@Service
class AuthService(
    private val googleTokenVerifier: GoogleTokenVerifier,
    private val userRepository: UserRepository,
    private val refreshTokenService: RefreshTokenService,
    private val jwtService: JwtService,
    private val refreshTokenRepository: RefreshTokenRepository
) {

    @Transactional
    fun googleLogin(authRequest: AuthRequest): AuthResponse {
        // Verify token with Google Web Token
        val googleUser = googleTokenVerifier.verify(token = authRequest.idToken)
        // Find if the user exist in database
        val user =
            userRepository.findByGoogleId(googleId = googleUser.googleId) ?: userRepository.save(googleUser.toEntity())

        val accessToken = jwtService.generateAccessToken(userId = user.id)
        val refreshToken = refreshTokenService.create(user = user)

        return AuthResponse(
            accessToken = accessToken,
            refreshToken = refreshToken,
        )
    }

    @Transactional
    fun refresh(request: RefreshRequest): RefreshResponse {
        val incomingHash = hashToken(token = request.refreshToken)
        val refreshToken =
            refreshTokenRepository.findByTokenHash(token = incomingHash) ?: throw InvalidRefreshTokenException()

        if (refreshToken.revoked) {
            // Grace period: If token was rotated within the last 5 minutes (e.g. parallel requests, offline sync retries),
            // safely issue a new access token instead of killing the user session.
            val gracePeriodWindow = Instant.now().minusSeconds(300)
            if (refreshToken.updatedAt.isAfter(gracePeriodWindow) && refreshToken.expiresAt.isAfter(Instant.now())) {
                val accessToken = jwtService.generateAccessToken(userId = refreshToken.user.id)
                return RefreshResponse(accessToken = accessToken, refreshToken = request.refreshToken)
            }
            throw InvalidRefreshTokenException()
        }

        if (refreshToken.expiresAt.isBefore(Instant.now())) {
            refreshToken.revoked = true
            refreshToken.updatedAt = Instant.now()
            refreshTokenRepository.save(refreshToken)
            throw InvalidRefreshTokenException()
        }

        // Revoke current token (Token Rotation)
        refreshToken.revoked = true
        refreshToken.updatedAt = Instant.now()
        refreshTokenRepository.save(refreshToken)

        val newRawRefreshToken = refreshTokenService.create(user = refreshToken.user)
        val accessToken = jwtService.generateAccessToken(userId = refreshToken.user.id)
        return RefreshResponse(accessToken = accessToken, refreshToken = newRawRefreshToken)
    }

    @Transactional
    fun logout(request: LogoutRequest) {
        val incomingHash = hashToken(token = request.refreshToken)
        val refreshToken = refreshTokenRepository.findByTokenHash(token = incomingHash) ?: throw InvalidRefreshTokenException()
        refreshToken.revoked = true
        refreshToken.updatedAt = Instant.now()
    }

}