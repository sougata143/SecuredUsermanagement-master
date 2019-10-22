package com.easybusiness.usermanagement.repository.CustomRepository;

import java.util.List;

import com.easybusiness.usermanagement.entity.UserProfession;

public interface UserProfessionCustomRepository {


    void addUserProfession(UserProfession userProfession);

    List<UserProfession> getAllUserProfessions();
    
    void updateUserProfession(UserProfession userProfession);

}
