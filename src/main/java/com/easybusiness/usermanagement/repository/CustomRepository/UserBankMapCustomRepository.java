package com.easybusiness.usermanagement.repository.CustomRepository;

import java.util.List;

import com.easybusiness.usermanagement.entity.UserBankMap;

public interface UserBankMapCustomRepository {

    UserBankMap getUserBankMapById(Long id);

    void deleteUserBankMap(Long id);

    void updateUserBankMap(UserBankMap userBankMap);

    void addUserBankMap(UserBankMap userBankMap);

    List<UserBankMap> getAllUserBankMaps();

}
