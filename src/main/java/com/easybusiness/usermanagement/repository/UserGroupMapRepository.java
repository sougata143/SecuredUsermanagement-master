package com.easybusiness.usermanagement.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import com.easybusiness.usermanagement.entity.User;
import com.easybusiness.usermanagement.entity.UserGroup;
import com.easybusiness.usermanagement.entity.UserGroupMap;
import com.easybusiness.usermanagement.repository.CustomRepository.UserGroupMapCustomRepository;

public interface UserGroupMapRepository extends CrudRepository<UserGroupMap, Long>, UserGroupMapCustomRepository {

    Optional<UserGroupMap> findById(Long i);

    List<UserGroupMap> findByUser(User user);
    
    List<UserGroupMap> findByUserGroup(UserGroup userGroup);
    
    List<UserGroupMap> findByUserAndUserGroup(User user,UserGroup userGroup);

}
