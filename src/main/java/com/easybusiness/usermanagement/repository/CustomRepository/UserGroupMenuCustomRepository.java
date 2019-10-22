package com.easybusiness.usermanagement.repository.CustomRepository;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.easybusiness.usermanagement.entity.UserGroupMenu;

public interface UserGroupMenuCustomRepository {

    UserGroupMenu getUserGroupMenuById(Long id);

    @Query("update UserGroupMenu set isEnable = 0 where id = :id")
    void deleteUserGroupMenu(@Param("id") Long id);

    void updateUserGroupMenu(UserGroupMenu userGroupMenu);

    void addUserGroupMenu(UserGroupMenu userGroupMenu);

    List<UserGroupMenu> getAllUserGroupMenus();

}
