package com.easybusiness.usermanagement.repository.CustomRepository;

import java.util.List;

import com.easybusiness.usermanagement.entity.UserAcademics;

public interface UserAcademicsCustomRepository {


    void addUserAcademics(UserAcademics userAcademics);

    List<UserAcademics> getAllUserAcademics();
    
    void updateUserAcademics(UserAcademics userAcademics);

}
