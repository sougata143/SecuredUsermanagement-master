package com.easybusiness.usermanagement.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;

import com.easybusiness.usermanagement.entity.User;
import com.easybusiness.usermanagement.entity.UserProfession;
import com.easybusiness.usermanagement.repository.CustomRepository.UserProfessionCustomRepository;

public interface UserProfessionRepository extends CrudRepository<UserProfession, Long>, UserProfessionCustomRepository {

    Optional<UserProfession> findById(Long i);

    List<UserProfession> findByUser(Long userId);
    
    @Query("select p from UserProfession p where p.user = :user")
    UserProfession findByUserid(@Param("user") Long user);
    
    /*@Query("select p from UserProfession p order by p.id group by p.organisation")
    List<UserProfession> findOrderByIdGroupById(Long userId);*/
    

}
