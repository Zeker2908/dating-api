package ru.zeker.userservice.service.imp;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.zeker.userservice.domain.model.User;
import ru.zeker.userservice.exception.UserAlreadyExistsException;
import ru.zeker.userservice.exception.UserNotFoundException;
import ru.zeker.userservice.repository.UserRepository;
import ru.zeker.userservice.service.UserService;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository repository;

    @Override
    public User findByEmail(String email) {
        return repository.findByEmail(email).orElseThrow((UserNotFoundException::new));
    }

    @Override
    public User findById(UUID id) {
        return repository.findById(id).orElseThrow((UserNotFoundException::new));
    }

    @Override
    @Transactional
    public User create(User user){
        if(repository.existsByEmail(user.getEmail())){
            throw new UserAlreadyExistsException();
        }
        return repository.save(user);
    }

    @Override
    @Transactional
    public User update(User user) {
       if(!repository.existsByEmail(user.getEmail())){
           throw new UserNotFoundException();
       }
       return repository.save(user);
    }

    @Override
    @Transactional
    public void deleteById(UUID id) {
        var user = repository.findById(id).orElseThrow(UserNotFoundException::new);
        repository.delete(user);

    }

    @Override
    @Transactional
    public void deleteByEmail(String email) {
        var user = repository.findByEmail(email).orElseThrow(UserNotFoundException::new);
        repository.delete(user);
    }

    @Override
    public boolean existsByEmail(String email) {
        return repository.existsByEmail(email);
    }


}
