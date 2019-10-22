package com.easybusiness.usermanagement.repository.repositoryimpl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.springframework.stereotype.Repository;

import com.easybusiness.usermanagement.entity.Bank;
import com.easybusiness.usermanagement.repository.CustomRepository.BankCustomRepository;

@Transactional
@Repository
public class BankRepositoryImpl implements BankCustomRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public Bank getBankById(Long bankId) {
	return entityManager.find(Bank.class, bankId);
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<Bank> getAllBanks() {
	String hql = "FROM Bank as bank ORDER BY bank.id";
	return (List<Bank>) entityManager.createQuery(hql).getResultList();
    }

    @Override
    public void addBank(Bank bank) {
	entityManager.persist(bank);
    }

    @Override
    public void updateBank(Bank bank) {
	Bank BankItem = getBankById(bank.getId());
	/*
	 * menu.setTitle(Menu.getTitle()); menu.setCategory(Menu.getCategory());
	 */
	entityManager.flush();
    }

    @Override
    public void deleteBank(Long bankId) {
	entityManager.remove(getBankById(bankId));
    }

}
