package ru.zeker.user_service.service;

import ru.zeker.user_service.domain.model.VerificationToken;

public interface VerificationTokenService {
    VerificationToken create(VerificationToken verificationToken);
    VerificationToken findByToken(String token);
    VerificationToken verify(String token);
    void delete(VerificationToken verificationToken);
}
