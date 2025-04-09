package ru.zeker.user_service.service.imp;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import ru.zeker.user_service.domain.model.VerificationToken;
import ru.zeker.user_service.exception.VerificationTokenNotFoundException;
import ru.zeker.user_service.repository.VerificationTokenRepository;
import ru.zeker.user_service.service.VerificationTokenService;

@Service
@RequiredArgsConstructor
public class VerificationTokenServiceImpl implements VerificationTokenService {
    private final VerificationTokenRepository verificationTokenRepository;

    @Override
    public VerificationToken create(VerificationToken verificationToken) {
        return verificationTokenRepository.save(verificationToken);
    }

    @Override
    public VerificationToken findByToken(String token) {
        return verificationTokenRepository.findByToken(token).orElseThrow(VerificationTokenNotFoundException::new);
    }
}
