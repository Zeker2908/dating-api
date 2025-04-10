package ru.zeker.user_service.service.imp;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
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

    @Override
    @Transactional
    public VerificationToken verify(String token) {
        return verificationTokenRepository.findByToken(token).map(vt -> {
            if(vt.getExpiryDate().isBefore(java.time.LocalDateTime.now())) {
                verificationTokenRepository.delete(vt);
                throw new VerificationTokenNotFoundException("Verification token expired");
            }
            return vt;
        }).orElseThrow(VerificationTokenNotFoundException::new);
    }
}

