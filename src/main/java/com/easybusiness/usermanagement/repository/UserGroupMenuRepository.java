package com.easybusiness.usermanagement.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import com.easybusiness.usermanagement.entity.Menu;
import com.easybusiness.usermanagement.entity.UserGroup;
import com.easybusiness.usermanagement.entity.UserGroupMenu;
import com.easybusiness.usermanagement.repository.CustomRepository.UserGroupMenuCustomRepository;

public interface UserGroupMenuRepository extends CrudRepository<UserGroupMenu, Long>, UserGroupMenuCustomRepository {

    Optional<UserGroupMenu> findById(Long i);

    List<UserGroupMenu> findByUserGroup(UserGroup userGroup);

    List<UserGroupMenu> findByMenuItem(Menu menu);
    
    List<UserGroupMenu> findByUserGroupAndMenuItem(UserGroup userGroup,Menu menu);

}
