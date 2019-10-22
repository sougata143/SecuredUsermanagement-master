package com.easybusiness.usermanagement.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import com.easybusiness.usermanagement.entity.Role;
import com.easybusiness.usermanagement.entity.RoleActionMap;
import com.easybusiness.usermanagement.repository.CustomRepository.RoleActionMapCustomRepository;

public interface RoleActionMapRepository extends CrudRepository<RoleActionMap, Long>, RoleActionMapCustomRepository {

    Optional<RoleActionMap> findById(Long i);

    List<RoleActionMap> findByRole(Role role);

}
