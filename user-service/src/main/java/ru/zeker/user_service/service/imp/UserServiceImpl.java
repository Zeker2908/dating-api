package ru.zeker.user_service.service.imp;

import jakarta.persistence.EntityExistsException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import ru.zeker.user_service.domain.model.User;
import ru.zeker.user_service.repository.UserRepository;
import ru.zeker.user_service.service.UserService;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository repository;

    @Override
    public User loadByEmail(String email) {
        return repository.findByEmail(email).orElseThrow(()->new UsernameNotFoundException("User not found"));
    }

    @Override
    public User create(User user){
        if(repository.existsByEmail(user.getEmail())){
            throw new EntityExistsException("User already exists");
        }
        return repository.save(user);
    }


}
