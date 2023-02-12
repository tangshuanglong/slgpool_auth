<?php declare(strict_types=1);

namespace App\Aspect;
use Swoft\Aop\Annotation\Mapping\Aspect;
use Swoft\Aop\Annotation\Mapping\PointBean;
use Swoft\Aop\Annotation\Mapping\After;
use Swoft\Aop\Annotation\Mapping\Before;
use Swoft\Aop\Annotation\Mapping\AfterReturning;
use Swoft\Aop\Point\JoinPoint;

/**
 * Class AuthAspect
 * @package App\Aspect
 *
 * Author j
 * Date 2019/11/28
 *
 * @Aspect(order=1)
 *
 * @PointBean(include={"App\Http\Controller\Api\AuthController"})
 */
class AuthAspect{

}
