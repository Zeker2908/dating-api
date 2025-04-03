package ru.zeker.user_service.service.imp;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.zeker.user_service.domain.model.User;
import ru.zeker.user_service.exception.UserAlreadyExistsException;
import ru.zeker.user_service.exception.UserNotFoundException;
import ru.zeker.user_service.repository.UserRepository;
import ru.zeker.user_service.service.UserService;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository repository;

    @Override
    public User findByEmail(String email) {
        return repository.findByEmail(email).orElseThrow((UserNotFoundException::new));
    }

    @Override
    public User create(User user){
        if(repository.existsByEmail(user.getEmail())){
            throw new UserAlreadyExistsException();
        }
        return repository.save(user);
    }

    @Override
    public User update(User user) {
       if(!repository.existsByEmail(user.getEmail())){
           throw new UserNotFoundException();
       }
       return repository.save(user);
    }

    @Override
    @Transactional
    public void deleteById(Long id) {
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
