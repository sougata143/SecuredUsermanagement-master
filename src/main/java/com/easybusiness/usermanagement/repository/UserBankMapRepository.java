package com.easybusiness.usermanagement.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import com.easybusiness.usermanagement.entity.Bank;
import com.easybusiness.usermanagement.entity.Branch;
import com.easybusiness.usermanagement.entity.User;
import com.easybusiness.usermanagement.entity.UserBankMap;
import com.easybusiness.usermanagement.repository.CustomRepository.UserBankMapCustomRepository;

public interface UserBankMapRepository extends CrudRepository<UserBankMap, Long>, UserBankMapCustomRepository {

    Optional<UserBankMap> findById(Long i);

    List<UserBankMap> findByBank(Bank bank);
    
    List<UserBankMap> findByBranch(Branch branch);
    
    List<UserBankMap> findByUser(User user);

}
