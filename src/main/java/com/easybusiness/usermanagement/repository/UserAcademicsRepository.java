package com.easybusiness.usermanagement.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import com.easybusiness.usermanagement.entity.User;
import com.easybusiness.usermanagement.entity.UserAcademics;
import com.easybusiness.usermanagement.repository.CustomRepository.UserAcademicsCustomRepository;

public interface UserAcademicsRepository extends CrudRepository<UserAcademics, Long>, UserAcademicsCustomRepository {

    Optional<UserAcademics> findById(Long i);

    //List<UserAcademics> findByUser(User user);
    
    List<UserAcademics> findByUser(Long long1);

}
