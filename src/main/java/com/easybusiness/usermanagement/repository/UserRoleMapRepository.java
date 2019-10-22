package com.easybusiness.usermanagement.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import com.easybusiness.usermanagement.entity.Role;
import com.easybusiness.usermanagement.entity.User;
import com.easybusiness.usermanagement.entity.UserRoleMap;
import com.easybusiness.usermanagement.repository.CustomRepository.UserRoleMapCustomRepository;

public interface UserRoleMapRepository extends CrudRepository<UserRoleMap, Long>, UserRoleMapCustomRepository {

    Optional<UserRoleMap> findById(Long i);

    List<UserRoleMap> findByUser(User user);
    
    List<UserRoleMap> findByRole(Role role);

}
