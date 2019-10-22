package com.easybusiness.usermanagement.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import com.easybusiness.usermanagement.entity.UserGroupMap;
import com.easybusiness.usermanagement.entity.UserMenu;
import com.easybusiness.usermanagement.repository.CustomRepository.UserMenuCustomRepository;

public interface UserMenuRepository extends CrudRepository<UserMenu, Long>, UserMenuCustomRepository {

    Optional<UserMenu> findById(Long i);

    List<UserMenu> findByUserGroupMap(UserGroupMap userGroupMap);

}
