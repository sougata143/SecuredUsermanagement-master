package com.easybusiness.usermanagement.entity.metadata;

import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

import com.easybusiness.usermanagement.entity.User;
import com.easybusiness.usermanagement.entity.UserAcademics;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(UserAcademics.class)
public abstract class UserAcademics_ {

    public static volatile SingularAttribute<UserAcademics, String> college;
    public static volatile SingularAttribute<UserAcademics, String> highestDegree;
    public static volatile SingularAttribute<UserAcademics, String> university;
    public static volatile SingularAttribute<UserAcademics, Long> id;
    public static volatile SingularAttribute<UserAcademics, String> marks;
    public static volatile SingularAttribute<UserAcademics, User> user;
    public static volatile SingularAttribute<UserAcademics, String> passOutYear;
    public static volatile SingularAttribute<UserAcademics, String> certificateName;
    public static volatile SingularAttribute<UserAcademics, String> certifiedBy;
    public static volatile SingularAttribute<UserAcademics, String> certificationYear;

}
