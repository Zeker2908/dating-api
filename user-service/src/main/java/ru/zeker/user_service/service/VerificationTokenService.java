package ru.zeker.user_service.service;

import ru.zeker.user_service.domain.model.VerificationToken;

import java.util.Optional;

public interface VerificationTokenService {
    VerificationToken create(VerificationToken verificationToken);
    VerificationToken findByToken(String token);
}
