package com.easybusiness.usermanagement.repository.repositoryimpl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.springframework.stereotype.Repository;

import com.easybusiness.usermanagement.entity.User;
import com.easybusiness.usermanagement.repository.CustomRepository.UserCustomRepository;

@Transactional
@Repository
public class UserRepositoryImpl implements UserCustomRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public User getUserById(Long userId) {
    	User user = entityManager.find(User.class, userId);
    	
	return user;
	
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<User> getAllUsers() {
	String hql = "FROM User as user ORDER BY user.id";
	return (List<User>) entityManager.createQuery(hql).getResultList();
    }

    @Override
    public void addUser(User user) {
	entityManager.merge(user);
	
    }

    @Override
    public void updateUser(User user) {
	
//    User userItem = entityManager.find(User.class, user.getId());
    	User userItem = getUserById(user.getId());
	
	userItem.setAlternateEmail(user.getAlternateEmail());
	userItem.setCity(user.getCity());
	userItem.setCountry(user.getCountry());
	userItem.setDateOfBirth(user.getDateOfBirth());
	userItem.setDepartment(user.getDepartment());
	userItem.setDesignation(user.getDesignation());
	userItem.setEmail(user.getEmail());
	userItem.setEndDate(user.getEndDate());
	userItem.setFatherName(user.getFatherName());
	userItem.setFromDate(user.getFromDate());
	userItem.setGender(user.getGender());
	userItem.setIsEnabled(user.getIsEnabled());
	userItem.setLastName(user.getLastName());
	userItem.setMobile(user.getMobile());
	userItem.setModifiedBy(user.getModifiedBy());
	userItem.setModifiedOn(user.getModifiedOn());
	userItem.setOrganization(user.getOrganization());
	userItem.setPassport(user.getPassport());
	userItem.setPermAddr(user.getPermAddr());
	userItem.setSpouseName(user.getSpouseName());
	userItem.setState(user.getState());
	userItem.setTypeOfEmployment(user.getTypeOfEmployment());
	userItem.setZip(user.getZip());
	userItem.setId(user.getId());
	userItem.setLocation(user.getLocation());
	
	
	entityManager.merge(userItem);
	entityManager.flush();
    }

    @Override
    public void deleteUser(Long userId) {
	entityManager.remove(getUserById(userId));
    }

    @Override
    public boolean userExists(String userName, String password) {
	String hql = "FROM User as user WHERE user.userName = ? and user.password = ?";
	int count = entityManager.createQuery(hql).setParameter(1, userName).setParameter(2, password).getResultList()
		.size();
	return count > 0 ? true : false;
    }

    @Override
    public int countOfUserNames(String userName) {
	String lowerCaseUserName=userName.toLowerCase();
	String hql = "FROM User as user WHERE LOWER(user.userName) like ?";
	int count = entityManager.createQuery(hql).setParameter(1, lowerCaseUserName+"%").getResultList()
		.size();
	return count;
    }

	@Override
	public List<User> getAllUserGroupByUName(String userName) {
		String hql = "FROM User as user WHERE user.userName = ? GROUP BY user.userName";
		return (List<User>) entityManager.createQuery(hql).setParameter(1, userName).getResultList();
	}

	@Override
	public void userCreateProc(Long inUserId, Long inLocationId) {
		entityManager.createNativeQuery("BEGIN USER_CREATE_PROC(:IN_USER_ID, :IN_LOCATION_ID); END;")
						.setParameter("IN_USER_ID", inUserId)
						.setParameter("IN_LOCATION_ID", inLocationId)
						.executeUpdate();
		
	}

}
