package com.easybusiness.usermanagement.repository.CustomRepository;

import java.util.List;

import com.easybusiness.usermanagement.entity.Bank;

public interface BankCustomRepository {

    Bank getBankById(Long bankId);

    void deleteBank(Long bankId);

    void updateBank(Bank Bank);

    void addBank(Bank Bank);

    List<Bank> getAllBanks();

}
