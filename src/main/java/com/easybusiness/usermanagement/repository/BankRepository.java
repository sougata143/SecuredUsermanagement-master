package com.easybusiness.usermanagement.repository;

import java.util.List;

import org.springframework.data.repository.CrudRepository;

import com.easybusiness.usermanagement.entity.Bank;
import com.easybusiness.usermanagement.repository.CustomRepository.BankCustomRepository;

public interface BankRepository extends CrudRepository<Bank, Long>, BankCustomRepository {

    List<Bank> findById(long id);

    List<Bank> findByBankName(String bankName);

    

}
