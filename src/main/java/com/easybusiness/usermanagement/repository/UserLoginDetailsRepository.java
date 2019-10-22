package com.easybusiness.usermanagement.repository;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;

import com.easybusiness.usermanagement.DTO.UserLoginDetailsDTO;
import com.easybusiness.usermanagement.entity.UserLoginDetails;
import com.easybusiness.usermanagement.repository.CustomRepository.UserLoginDetailsCustomRepository;

public interface UserLoginDetailsRepository extends CrudRepository<UserLoginDetails, Long>, UserLoginDetailsCustomRepository {

	UserLoginDetails findByLoginToken(String loginToken);
	
	@Query("select l from UserLoginDetails l where l.userName = :userName")
	List<UserLoginDetails> findByUserLoginId(@Param("userName") String userName);
	
}
