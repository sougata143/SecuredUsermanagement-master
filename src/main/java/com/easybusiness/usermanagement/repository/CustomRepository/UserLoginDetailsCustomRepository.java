package com.easybusiness.usermanagement.repository.CustomRepository;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.easybusiness.usermanagement.entity.UserLoginDetails;

public interface UserLoginDetailsCustomRepository {

	UserLoginDetails getLoginDetailsByUserId(Long userId);
	
	UserLoginDetails getLoginDetailsByLoginToken(String loginToken);
	
	public void saveLogin(UserLoginDetails login);
	
	UserLoginDetails update(UserLoginDetails userLoginDetails);
	
	@Query("update UserLoginDetails set isActive = 'N' where loginToken = :loginToken")
	UserLoginDetails updateCustom(@Param("loginToken") String loginToken);
	
}
