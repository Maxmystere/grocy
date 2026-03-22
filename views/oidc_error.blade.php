@extends('layout.default')

@section('title', $__t('Login error'))

@section('content')
<div class="row">
	<div class="col-lg-6 offset-lg-3 col-md-8 offset-md-2 col-12">
		<h2 class="text-center">@yield('title')</h2>

		<hr class="my-2">

		<div class="alert alert-danger">
			<i class="fa-solid fa-circle-exclamation"></i>
			{{ $errorMessage }}
		</div>

		<div class="text-center mt-3">
			<a href="{{ $U('/login') }}"
				class="btn btn-secondary">
				<i class="fa-solid fa-arrow-left"></i>
				{{ $__t('Back to login') }}
			</a>
		</div>
	</div>
</div>
@stop
