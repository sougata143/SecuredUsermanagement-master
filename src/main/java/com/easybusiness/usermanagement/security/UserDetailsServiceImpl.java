package com.easybusiness.usermanagement.security;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.easybusiness.usermanagement.dao.UserDao;
import com.easybusiness.usermanagement.dao.UserRoleMapDao;
import com.easybusiness.usermanagement.entity.UserRoleMap;
import com.easybusiness.usermanagement.entity.Users;


@Service
public class UserDetailsServiceImpl implements UserDetailsService {
	
	@Autowired
	UserDao userDao;
	
	@Autowired
	UserRoleMapDao roleDao;
	
	@Autowired
	UserDetailsService userDetailsService;
	
	List<Users> userList = new ArrayList<>();
	
	@Override
	public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
		List<UserRoleMap> role = roleDao.findByUser(userDao.findByUserName(userName).get());
		
		com.easybusiness.usermanagement.entity.User users = userDao.findByUserName(userName).get();
									/*.stream()
									.filter(u -> u.getUserName().equals(userName))
									.findAny();*/
		if(users == null) {
			throw new UsernameNotFoundException("Users not found by name "+userName);
		}
		System.out.println(users);
		System.out.println(role);
//		return new User(users.getUserName(), users.getPassword(), emptyList());
		return toUserDetails(users);
		
	}

	@SuppressWarnings("unused")
	private UserDetails toUserDetails(com.easybusiness.usermanagement.entity.User users) {
		UserRoleMap role = roleDao.findByUser(userDao.findByUserName(users.getUserName()).get()).get(0);
		UserDetails userDetails = User.withUsername(users.getUserName())
				.password(users.getPassword())
				.roles(role.getRole().getRole())
				.build();
		System.out.println("User Details " + userDetails);
		return userDetails;
	}

}
