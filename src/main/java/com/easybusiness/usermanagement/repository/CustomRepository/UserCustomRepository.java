package com.easybusiness.usermanagement.repository.CustomRepository;

import java.util.List;

import com.easybusiness.usermanagement.entity.User;

public interface UserCustomRepository {

    User getUserById(Long userId);

    boolean userExists(String userName, String password);

    void deleteUser(Long userId);

    void updateUser(User user);

    void addUser(User user);

    List<User> getAllUsers();
    
    int countOfUserNames(String userName);
    
    List<User> getAllUserGroupByUName(String userName);
    
    void userCreateProc(Long long1, Long inLocationId);
    
    

}
